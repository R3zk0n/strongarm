#!/usr/bin/env python3
"""
Debug script for Swift metadata parsing.
This will help diagnose issues with finding and parsing Swift metadata sections.
"""

import sys
import logging
from pathlib import Path

from strongarm.macho import MachoParser, MachoBinary
from strongarm.macho.swift_metadata_parser import SwiftMetadataParser

# Setup logging to see debug messages
logging.basicConfig(
    level=logging.WARNING,  # Use WARNING to avoid strongarm's logging bugs
    format='%(name)s - %(levelname)s - %(message)s'
)


def test_swift_parsing(binary_path: str):
    """Test Swift metadata parsing with detailed logging."""

    print(f"\n{'=' * 80}")
    print(f"Testing Swift Metadata Parser")
    print(f"Binary: {binary_path}")
    print(f"{'=' * 80}\n")

    try:
        # Load the binary using MachoParser (correct strongarm API)
        print("[1/4] Loading Mach-O binary...")
        macho_parser = MachoParser(Path(binary_path))

        # Get the ARM64 slice (or try ARM64e, then x86_64 as fallback)
        binary = None
        try:
            binary = macho_parser.get_arm64_slice()
            print(f"      ✓ Loaded ARM64 slice from {binary_path}")
        except:
            try:
                binary = macho_parser.get_armv7_slice()
                print(f"      ✓ Loaded ARMv7 slice from {binary_path}")
            except:
                try:
                    binary = macho_parser.get_x86_64_slice()
                    print(f"      ✓ Loaded x86_64 slice from {binary_path}")
                except:
                    print(f"      ✗ Could not find any supported architecture slice")
                    return

        print(f"      Path: {binary.path}")


        # List all sections
        print("\n[2/4] Scanning for Swift-related sections...")
        swift_sections = []
        for section in binary.sections:
            section_name = section.name.rstrip('\x00')
            full_name = f"{section.segment_name}::{section_name}"

            if "swift" in section_name.lower():
                swift_sections.append((section.segment_name, section_name, section.size))
                print(f"      ✓ Found: {full_name} (size={section.size} bytes)")

        if not swift_sections:
            print("      ✗ No Swift sections found in binary!")
            print("        This may not be a Swift binary or Swift metadata was stripped.")
            return

        # Check for __swift5_types specifically
        print("\n[3/4] Looking for __swift5_types section...")
        has_types_section = any(name == "__swift5_types" for _, name, _ in swift_sections)

        if not has_types_section:
            print("      ✗ __swift5_types section not found!")
            print("        Available Swift sections:")
            for seg, name, size in swift_sections:
                print(f"          - {seg}::{name}")
            return
        else:
            types_size = next(size for _, name, size in swift_sections if name == "__swift5_types")
            print(f"      ✓ Found __swift5_types section ({types_size} bytes)")
            print(f"        Expected type descriptors: ~{types_size // 4}")

        # Parse Swift metadata
        print("\n[4/4] Parsing Swift metadata...")
        parser = SwiftMetadataParser(binary)

        print(f"\n{'=' * 80}")
        print(f"Results:")
        print(f"{'=' * 80}")
        print(f"Total types found:     {len(parser.types)}")
        print(f"Classes:               {len(parser.get_classes())}")
        print(f"Structs:               {len(parser.get_structs())}")
        print(f"Enums:                 {len(parser.get_enums())}")
        print(f"Encryption:            {(parser.binary.is_encrypted())}")
        print(f"Path Info:             {(parser.binary.path)}")
        print(f"Header Info:           {(parser.binary.file_offset)}")



        if parser.types:
            print(f"\n{'=' * 80}")
            print(f"Parsed Types (showing mangled -> demangled):")
            print(f"{'=' * 80}")
            for i, swift_type in enumerate(parser.types[:100], 1):
                kind_str = swift_type.kind.name.lower() if swift_type.kind else "unknown"
                field_count = len(swift_type.fields)

                # Show demangling result
                if swift_type.mangled_name != swift_type.name:
                    print(f"{i:2d}. [{kind_str:6s}] {swift_type.name} ({field_count} fields)")
                    print(f"     Mangled: {swift_type.mangled_name}")
                else:
                    print(f"{i:2d}. [{kind_str:6s}] {swift_type.name} ({field_count} fields) [not demangled]")

                # Show fields with demangling info
                for field in swift_type.fields[:100]:
                    var_let = "var" if field.is_var else "let"
                    if field.mangled_type_name != field.demangled_type_name:
                        print(f"     └─ {var_let} {field.name}: {field.demangled_type_name}")
                        print(f"        (mangled: {field.mangled_type_name})")
                    else:
                        print(f"     └─ {var_let} {field.name}: {field.demangled_type_name} [not demangled]")

                if len(swift_type.fields) > 100:
                    print(f"     └─ ... and {len(swift_type.fields) - 100} more fields")

            # Demangling statistics
            print(f"\n{'=' * 80}")
            print(f"Demangling Statistics:")
            print(f"{'=' * 80}")
            types_demangled = sum(1 for t in parser.types if t.mangled_name != t.name)
            total_fields = sum(len(t.fields) for t in parser.types)
            fields_demangled = sum(
                1 for t in parser.types
                for f in t.fields
                if f.mangled_type_name != f.demangled_type_name
            )
            print(f"Type names demangled:  {types_demangled}/{len(parser.types)}")
            print(f"Field types demangled: {fields_demangled}/{total_fields}")

        else:
            print("\n⚠ No types were parsed. Possible reasons:")
            print("  1. Section exists but is empty")
            print("  2. Parsing error (check debug logs above)")
            print("  3. Binary uses a different Swift ABI version")

        print(f"\n{'=' * 80}\n")

    except ImportError as e:
        print(f"\n✗ Import error: {e}")
        print("  Make sure strongarm is installed properly")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 SwiftParsing.py <path_to_binary>")
        print("\nExample:")
        print("  python3 SwiftParsing.py /tmp/DVIA-v2")
        sys.exit(1)

    binary_path = sys.argv[1]

    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)

    test_swift_parsing(binary_path)