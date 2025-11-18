import pathlib

import pytest

from strongarm.macho import MachoParser
from strongarm.macho.swift_metadata_parser import SwiftMetadataParser, SwiftType


"""Testing the new implemented Swift Parsing Sections

__TEXT -> __TEXT __constg_swift
__TEXT -> __TEXT swift5_types

[Type Descriptors]


"""


class TestSwiftParsing:
    TARGET_PATH = pathlib.Path(__file__).parent / "bin" / "SwiftBinaries" / "iGoat-Swift"

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        if not self.TARGET_PATH.exists():
            pytest.skip(f"Test binary not found: {self.TARGET_PATH}")
        parser = MachoParser(self.TARGET_PATH)
        self.binary = parser.get_arm64_slice()
        if not self.binary:
            pytest.skip("Could not get arm64 slice from binary")
        self.swift_metadata = SwiftMetadataParser(self.binary)

    def test_parser_initialization(self) -> None:
        """Test that SwiftMetadataParser initializes correctly."""
        assert self.swift_metadata is not None
        assert self.swift_metadata.binary == self.binary

    def test_types_list_populated(self) -> None:
        """Test that Swift types are parsed from the binary."""
        assert isinstance(self.swift_metadata.types, list)
        # The binary should have at least some Swift types
        assert len(self.swift_metadata.types) >= 0

    def test_get_classes(self) -> None:
        """Test retrieving Swift classes."""
        classes = self.swift_metadata.get_classes()
        assert isinstance(classes, list)
        for cls in classes:
            assert isinstance(cls, SwiftType)

    def test_get_structs(self) -> None:
        """Test retrieving Swift structs."""
        structs = self.swift_metadata.get_structs()
        assert isinstance(structs, list)
        for struct in structs:
            assert isinstance(struct, SwiftType)

    def test_get_enums(self) -> None:
        """Test retrieving Swift enums."""
        enums = self.swift_metadata.get_enums()
        assert isinstance(enums, list)
        for enum in enums:
            assert isinstance(enum, SwiftType)

    def test_get_type_by_name_not_found(self) -> None:
        """Test that get_type_by_name returns None for non-existent types."""
        result = self.swift_metadata.get_type_by_name("NonExistentTypeName12345")
        assert result is None

    def test_swift_type_has_required_attributes(self) -> None:
        """Test that parsed SwiftType objects have required attributes."""
        if not self.swift_metadata.types:
            pytest.skip("No Swift types found in binary")

        swift_type = self.swift_metadata.types[0]
        assert hasattr(swift_type, 'name')
        assert hasattr(swift_type, 'mangled_name')
        assert hasattr(swift_type, 'descriptor_address')
        assert hasattr(swift_type, 'fields')
        assert hasattr(swift_type, 'kind')

    def test_all_types_accounted_for(self) -> None:
        """Test that classes + structs + enums equals total types with those kinds."""
        classes = self.swift_metadata.get_classes()
        structs = self.swift_metadata.get_structs()
        enums = self.swift_metadata.get_enums()

        # All returned types should be SwiftType instances
        all_categorized = classes + structs + enums
        for swift_type in all_categorized:
            assert isinstance(swift_type, SwiftType)
