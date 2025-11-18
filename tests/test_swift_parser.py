import pathlib
from distutils.version import LooseVersion
from typing import List
from unittest.mock import MagicMock

from strongarm.macho import MachoParser, ObjcCategory, ObjcMethodStruct, ObjcRuntimeDataParser, ObjcSelector


"""Testing the new implemented Swift Parsing Sections

__TEXT -> __TEXT __constg_swift 
__TEXT -> __TEXT swift5_types

[Type Descriptors]


"""