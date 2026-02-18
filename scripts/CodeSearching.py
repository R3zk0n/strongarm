from strongarm.macho import MachoParser, MachoBinary, VirtualMemoryPointer
from strongarm.cli.utils import MachoAnalyzer
from pathlib import Path
from strongarm.objc import ObjcFunctionAnalyzer, RegisterContentsType
from strongarm.macho import MachoAnalyzer, MachoParser
from strongarm.macho import MachoAnalyzer, MachoParser
from strongarm.objc import CodeSearch, CodeSearchTermCallDestination
import argparse

# Define a class
class CodeSearcher:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.analyzer = None
        self.binary = None

    def load_binary(self):
        """Load the Mach-O binary and initialize the analyzer."""
        parser = MachoParser(Path(self.binary_path))
        self.binary = parser.get_arm64_slice()
        if not self.binary:
            raise Exception("Could not get arm64 slice from binary")
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)



# Define main
if __name__ == "__main__":
    # Example usage
    # Use argparse to allow passing the binary path as a command-line argument
    parser = argparse.ArgumentParser(description="Search for specific code patterns in a Mach-O binary.")
    parser.add_argument("binary_path", help="Path to the Mach-O binary to analyze")
    args = parser.parse_args()

    searcher = CodeSearcher(args.binary_path)
