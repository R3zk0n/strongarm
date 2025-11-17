# strongarm/macho/swift_metadata_parser.py

from ctypes import Structure, c_int16, c_int32, c_uint16, c_uint32, c_uint64, sizeof
from enum import IntEnum
from typing import Dict, List, Optional

from strongarm.logger import strongarm_logger
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_definitions import VirtualMemoryPointer

logger = strongarm_logger.getChild(__file__)


# ============================================================================
# Swift Metadata Raw Structure Definitions (ctypes)
# ============================================================================

class SwiftTypeDescriptorRaw(Structure):
    """
    Swift Type Descriptor structure from __swift5_types section.

    Reference: https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h
    """
    _fields_ = [
        ("flags", c_uint32),  # Type descriptor flags
        ("parent", c_int32),  # relative<ContextDescriptor>
        ("name", c_int32),  # relative<char> - mangled type name
        ("access_function_pointer", c_int32),  # relative<void> - metadata accessor
        ("fields", c_int32),  # relative<FieldDescriptor>
        ("superclass_type", c_int32),  # relative<char> - for classes
        ("metadata_negative_size", c_uint32),  # Size below metadata pointer
        ("metadata_positive_size", c_uint32),  # Size above metadata pointer
        ("num_immediate_members", c_uint32),  # Number of immediate members
        ("num_fields", c_uint32),  # Number of fields in type
        ("field_offset_vector_offset", c_uint32),  # Offset to field offsets
    ]


class SwiftFieldDescriptorRaw(Structure):
    """
    Field Descriptor structure - describes fields for a type.

    The fields array follows immediately after this structure.
    """
    _fields_ = [
        ("mangled_type_name", c_int32),  # relative<char> - type name
        ("superclass", c_int32),  # relative<char> - superclass name
        ("kind", c_uint16),  # FieldDescriptorKind
        ("field_record_size", c_uint16),  # Size of each FieldRecord
        ("num_fields", c_uint32),  # Number of fields
        # FieldRecord array follows immediately
    ]


class SwiftFieldRecordRaw(Structure):
    """
    Individual Field Record - describes one field in a type.
    """
    _fields_ = [
        ("flags", c_uint32),  # Field flags (var/let, etc.)
        ("mangled_type_name", c_int32),  # relative<char> - field type
        ("name", c_int32),  # relative<char> - field name
    ]


# ============================================================================
# Enumerations
# ============================================================================

class SwiftFieldDescriptorKind(IntEnum):
    """Kind of type the field descriptor describes"""
    STRUCT = 0
    CLASS = 1
    ENUM = 2
    MULTI_PAYLOAD_ENUM = 3
    PROTOCOL = 4
    CLASS_PROTOCOL = 5
    OBJC_PROTOCOL = 6
    OBJC_CLASS = 7


class SwiftFieldFlags(IntEnum):
    """Flags in FieldRecord.flags"""
    IS_VAR = 0x1  # Set if field is 'var' (mutable)
    IS_INDIRECT = 0x2  # Set if field is stored indirectly


# ============================================================================
# High-Level Swift Metadata Objects
# ============================================================================

class SwiftField:
    """Represents a single field in a Swift type"""
    __slots__ = ["name", "mangled_type_name", "demangled_type_name",
                 "flags", "is_var", "is_indirect"]

    def __init__(self, name: str, mangled_type_name: str, flags: int):
        self.name = name
        self.mangled_type_name = mangled_type_name
        self.demangled_type_name = mangled_type_name  # Updated by parser
        self.flags = flags
        self.is_var = bool(flags & SwiftFieldFlags.IS_VAR)
        self.is_indirect = bool(flags & SwiftFieldFlags.IS_INDIRECT)

    def __repr__(self) -> str:
        kind = "var" if self.is_var else "let"
        return f"<SwiftField {kind} {self.name}: {self.demangled_type_name}>"

    def __str__(self) -> str:
        kind = "var" if self.is_var else "let"
        return f"{kind} {self.name}: {self.demangled_type_name}"


class SwiftType:
    """Represents a Swift type from metadata"""
    __slots__ = ["name", "mangled_name", "descriptor_address", "fields",
                 "superclass_name", "mangled_superclass_name", "kind",
                 "flags", "num_fields"]

    def __init__(self, mangled_name: str, descriptor_address: VirtualMemoryPointer, flags: int):
        self.mangled_name = mangled_name
        self.name = mangled_name  # Will be updated with demangled version
        self.descriptor_address = descriptor_address
        self.fields: List[SwiftField] = []
        self.superclass_name: Optional[str] = None
        self.mangled_superclass_name: Optional[str] = None
        self.kind: Optional[SwiftFieldDescriptorKind] = None
        self.flags = flags
        self.num_fields = 0

    def __repr__(self) -> str:
        kind_str = self.kind.name.lower() if self.kind else "type"
        field_info = f"{len(self.fields)} fields" if self.fields else "no fields"
        return f"<SwiftType {kind_str} {self.name} ({field_info})>"

    def __str__(self) -> str:
        lines = []
        kind_str = self.kind.name.lower() if self.kind else "type"

        # Header with superclass if present
        if self.superclass_name:
            lines.append(f"{kind_str} {self.name}: {self.superclass_name} {{")
        else:
            lines.append(f"{kind_str} {self.name} {{")

        # Fields
        for field in self.fields:
            lines.append(f"    {field}")

        lines.append("}")
        return "\n".join(lines)


# ============================================================================
# Main Parser
# ============================================================================

class SwiftMetadataParser:
    """Parser for Swift 5.x metadata sections"""

    def __init__(self, binary: MachoBinary):
        self.binary = binary
        logger.debug(f"Parsing Swift metadata of {self.binary}...")

        self.types: List[SwiftType] = []
        self._type_cache: Dict[VirtualMemoryPointer, SwiftType] = {}

        self._parse_type_descriptors()
        logger.debug(f"Parsed {len(self.types)} Swift types")

    # ========================================================================
    # Relative Pointer Resolution
    # ========================================================================

    def _resolve_relative_pointer(self, pointer_address: VirtualMemoryPointer,
                                  offset: int) -> VirtualMemoryPointer:
        """
        Resolve a Swift relative pointer to an absolute address.

        Swift uses 32-bit signed relative offsets from the pointer location.

        Args:
            pointer_address: Address where the relative pointer is stored
            offset: The 32-bit signed offset value (already properly signed from c_int32)

        Returns:
            Absolute virtual memory address
        """
        # c_int32 already handles sign extension, so just add the offset
        # No manual sign extension needed!
        return VirtualMemoryPointer(pointer_address + offset)

    def _read_relative_string(self, pointer_address: VirtualMemoryPointer) -> Optional[str]:
        """
        Read a string via a relative pointer.

        Args:
            pointer_address: Address where the relative pointer is stored

        Returns:
            The string, or None if null pointer or read failed
        """
        # Read the 32-bit relative offset
        offset = self.binary.read_word(pointer_address, word_type=c_int32, virtual=True)

        # Check for null pointer (offset of 0)
        if offset == 0:
            return None

        # Resolve to absolute address
        string_address = self._resolve_relative_pointer(pointer_address, offset)

        # Read the string
        return self.binary.get_full_string_from_start_address(string_address, virtual=True)

    # ========================================================================
    # Type Descriptor Parsing
    # ========================================================================

    def _parse_type_descriptors(self) -> None:
        """
        Parse all type descriptors from the __swift5_types section.

        The __swift5_types section contains an array of 32-bit relative offsets,
        each pointing to a TypeDescriptor structure.
        """
        # Find the __swift5_types section
        types_section = None

        # Debug: log all available sections
        logger.debug(f"Searching for __swift5_types section. Available sections:")
        for section in self.binary.sections:
            section_name = section.name.rstrip('\x00')  # Strip null padding
            logger.debug(f"  - {section.segment_name}::{section_name}")
            if section_name == "__swift5_types":
                types_section = section
                break

        if not types_section:
            logger.warning("No __swift5_types section found in binary")
            return

        logger.debug(
            f"Found __swift5_types section at {hex(types_section.address)}, "
            f"size={types_section.size}"
        )

        # Each entry is a 32-bit relative offset to a TypeDescriptor
        entry_size = 4  # sizeof(int32_t)
        num_entries = types_section.size // entry_size

        logger.debug(f"Parsing {num_entries} type descriptor entries")

        # Iterate through each entry
        current_addr = types_section.address
        for i in range(num_entries):
            try:
                # Read the relative offset (32-bit signed)
                offset = self.binary.read_word(current_addr, word_type=c_int32, virtual=True)

                # Resolve to absolute address
                descriptor_addr = self._resolve_relative_pointer(current_addr, offset)

                logger.debug(
                    f"Entry {i}: offset={offset}, descriptor at {hex(descriptor_addr)}"
                )

                # Parse the type descriptor
                swift_type = self._parse_single_type_descriptor(descriptor_addr)

                if swift_type:
                    self.types.append(swift_type)
                    self._type_cache[descriptor_addr] = swift_type
                    logger.debug(f"Parsed type: {swift_type.name}")

            except Exception as e:
                logger.error(f"Failed to parse type descriptor entry {i} at {hex(current_addr)}: {e}")

            # Move to next entry
            current_addr += entry_size

    def _parse_single_type_descriptor(self,
                                      descriptor_addr: VirtualMemoryPointer) -> Optional[SwiftType]:
        """
        Parse a single type descriptor.

        Args:
            descriptor_addr: Address of the SwiftTypeDescriptor

        Returns:
            SwiftType object, or None if parsing failed
        """
        # Read the type descriptor structure
        descriptor_data = self.binary.get_content_from_virtual_address(
            descriptor_addr, sizeof(SwiftTypeDescriptorRaw)
        )
        descriptor = SwiftTypeDescriptorRaw.from_buffer_copy(descriptor_data)

        # Read the mangled type name (relative pointer at name field offset)
        name_ptr_addr = descriptor_addr + SwiftTypeDescriptorRaw.name.offset
        mangled_name = self._read_relative_string(name_ptr_addr)

        if not mangled_name:
            logger.debug(f"Could not read type name at {hex(descriptor_addr)}")
            return None

        # Create SwiftType object
        swift_type = SwiftType(mangled_name, descriptor_addr, descriptor.flags)
        swift_type.num_fields = descriptor.num_fields

        # Attempt to demangle the type name
        demangled = self._demangle_swift_name(mangled_name)
        if demangled != mangled_name:
            swift_type.name = demangled

        # Parse superclass if present (non-zero offset)
        if descriptor.superclass_type != 0:
            superclass_ptr_addr = descriptor_addr + SwiftTypeDescriptorRaw.superclass_type.offset
            superclass_mangled = self._read_relative_string(superclass_ptr_addr)
            if superclass_mangled:
                swift_type.mangled_superclass_name = superclass_mangled
                swift_type.superclass_name = self._demangle_swift_name(superclass_mangled)

        # Parse field descriptor if present (non-zero offset)
        if descriptor.fields != 0:
            self._parse_field_descriptor(swift_type, descriptor_addr, descriptor)

        return swift_type

    # ========================================================================
    # Field Descriptor Parsing
    # ========================================================================

    def _parse_field_descriptor(self, swift_type: SwiftType,
                                type_descriptor_addr: VirtualMemoryPointer,
                                type_descriptor: SwiftTypeDescriptorRaw) -> None:
        """
        Parse the field descriptor for a type.

        Args:
            swift_type: The SwiftType to populate with fields
            type_descriptor_addr: Address of the parent TypeDescriptor
            type_descriptor: The parsed TypeDescriptor structure
        """
        # Resolve relative pointer to FieldDescriptor
        fields_ptr_addr = type_descriptor_addr + SwiftTypeDescriptorRaw.fields.offset
        fields_offset = type_descriptor.fields

        if fields_offset == 0:
            return  # No fields

        field_descriptor_addr = self._resolve_relative_pointer(fields_ptr_addr, fields_offset)

        # Read the FieldDescriptor structure
        try:
            field_desc_data = self.binary.get_content_from_virtual_address(
                field_descriptor_addr, sizeof(SwiftFieldDescriptorRaw)
            )
            field_descriptor = SwiftFieldDescriptorRaw.from_buffer_copy(field_desc_data)
        except Exception as e:
            logger.error(
                f"Failed to read field descriptor for {swift_type.name} "
                f"at {hex(field_descriptor_addr)}: {e}"
            )
            return

        # Store the kind
        try:
            swift_type.kind = SwiftFieldDescriptorKind(field_descriptor.kind)
        except ValueError:
            logger.warning(f"Unknown field descriptor kind: {field_descriptor.kind}")
            swift_type.kind = None

        logger.debug(
            f"Parsing {field_descriptor.num_fields} fields for {swift_type.name} "
            f"(kind={swift_type.kind.name if swift_type.kind else 'unknown'})"
        )

        # Parse each field record
        # Field records start immediately after the FieldDescriptor
        field_record_addr = field_descriptor_addr + sizeof(SwiftFieldDescriptorRaw)
        field_record_size = field_descriptor.field_record_size

        for i in range(field_descriptor.num_fields):
            field = self._parse_field_record(field_record_addr)
            if field:
                swift_type.fields.append(field)

            # Move to next field record
            field_record_addr += field_record_size

    def _parse_field_record(self, record_addr: VirtualMemoryPointer) -> Optional[SwiftField]:
        """
        Parse a single FieldRecord.

        Args:
            record_addr: Address of the FieldRecord structure

        Returns:
            SwiftField object, or None if parsing failed
        """
        try:
            # Read the FieldRecord structure
            record_data = self.binary.get_content_from_virtual_address(
                record_addr, sizeof(SwiftFieldRecordRaw)
            )
            record = SwiftFieldRecordRaw.from_buffer_copy(record_data)
        except Exception as e:
            logger.error(f"Failed to read field record at {hex(record_addr)}: {e}")
            return None

        # Read field name (relative pointer)
        name_ptr_addr = record_addr + SwiftFieldRecordRaw.name.offset
        field_name = self._read_relative_string(name_ptr_addr)

        if not field_name:
            logger.debug(f"Could not read field name at {hex(record_addr)}")
            return None

        # Read mangled type name (relative pointer)
        type_ptr_addr = record_addr + SwiftFieldRecordRaw.mangled_type_name.offset
        mangled_type = self._read_relative_string(type_ptr_addr)

        if not mangled_type:
            logger.debug(f"Could not read field type at {hex(record_addr)}")
            mangled_type = "<unknown>"

        # Create SwiftField
        field = SwiftField(field_name, mangled_type, record.flags)

        # Attempt to demangle the type name
        demangled_type = self._demangle_swift_name(mangled_type)
        if demangled_type != mangled_type:
            field.demangled_type_name = demangled_type

        return field

    # ========================================================================
    # Name Demangling
    # ========================================================================

    def _demangle_swift_name(self, mangled_name: str) -> str:
        """
        Attempt to demangle a Swift symbol name.

        This is a placeholder - integrate swift-demangle for production use.

        Args:
            mangled_name: Mangled Swift name (e.g., "$s4Test6PersonV")

        Returns:
            Demangled name, or original if demangling failed
        """
        # TODO: Integrate swift-demangle subprocess or binding
        # import subprocess
        # try:
        #     result = subprocess.check_output(
        #         ["swift-demangle", "-compact", mangled_name],
        #         stderr=subprocess.DEVNULL,
        #         timeout=1
        #     ).decode().strip()
        #     if result and result != mangled_name:
        #         return result
        # except Exception:
        #     pass

        return mangled_name

    # ========================================================================
    # Query Methods
    # ========================================================================

    def get_type_by_name(self, name: str) -> Optional[SwiftType]:
        """
        Find a type by its name (mangled or demangled).

        Args:
            name: Type name to search for

        Returns:
            SwiftType if found, None otherwise
        """
        for swift_type in self.types:
            if swift_type.name == name or swift_type.mangled_name == name:
                return swift_type
        return None

    def get_classes(self) -> List[SwiftType]:
        """Get all class types"""
        return [t for t in self.types if t.kind == SwiftFieldDescriptorKind.CLASS]

    def get_structs(self) -> List[SwiftType]:
        """Get all struct types"""
        return [t for t in self.types if t.kind == SwiftFieldDescriptorKind.STRUCT]

    def get_enums(self) -> List[SwiftType]:
        """Get all enum types"""
        return [t for t in self.types
                if t.kind in (SwiftFieldDescriptorKind.ENUM,
                              SwiftFieldDescriptorKind.MULTI_PAYLOAD_ENUM)]