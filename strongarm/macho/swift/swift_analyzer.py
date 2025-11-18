import functools
import shlex
from itertools import starmap
from subprocess import check_output
from typing import List, Optional

from capstone import CsInsn

from strongarm.logger import strongarm_logger
from strongarm.macho import MachoBinary, ObjcClass, ObjcSelector, VirtualMemoryPointer

from strongarm.macho import SwiftType, SwiftMetadataParser, SwiftFieldDescriptorKind, SwiftField

logger = strongarm_logger.getChild(__file__)
