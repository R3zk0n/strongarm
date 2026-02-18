from strongarm.macho import MachoParser, MachoBinary, VirtualMemoryPointer
from strongarm.cli.utils import MachoAnalyzer
from pathlib import Path
from strongarm.objc import ObjcFunctionAnalyzer, RegisterContentsType


def parse_binary(file_path):
    """Parse a Mach-O binary and return an analyzer instance."""
    parser = MachoParser(Path(file_path))
    binary = parser.get_arm64_slice()
    analyzer = MachoAnalyzer.get_analyzer(binary)
    return analyzer, binary


def disassemble_around_address(binary, address, instructions_before=10, instructions_after=5):
    """Disassemble instructions around a given address."""
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

        # Get some bytes before and after
        start_addr = address - (instructions_before * 4)  # ARM64 instructions are 4 bytes
        size = (instructions_before + instructions_after + 1) * 4

        code_bytes = binary.get_content_from_virtual_address(
            VirtualMemoryPointer(start_addr),
            size
        )

        # Disassemble
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True

        print(f"\n{'=' * 80}")
        print(f"Disassembly around {hex(address)} (showing {instructions_before} before, {instructions_after} after)")
        print(f"{'=' * 80}")

        for insn in md.disasm(code_bytes, start_addr):
            marker = " >>> " if insn.address == address else "     "
            print(f"{marker}{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}")

        print(f"{'=' * 80}\n")

    except ImportError:
        print("[!] capstone not installed. Install with: pip install capstone")
        print("[!] Falling back to basic instruction dump...\n")

        # Fallback: just show hex dump
        start_addr = address - 40
        code_bytes = binary.get_content_from_virtual_address(
            VirtualMemoryPointer(start_addr),
            80
        )

        print(f"\n{'=' * 80}")
        print(f"Hex dump around {hex(address)}")
        print(f"{'=' * 80}")
        for i in range(0, len(code_bytes), 4):
            addr = start_addr + i
            marker = " >>> " if addr == address else "     "
            instr_bytes = code_bytes[i:i + 4]
            hex_str = ' '.join(f'{b:02x}' for b in instr_bytes)
            print(f"{marker}{hex(addr)}:\t{hex_str}")
        print(f"{'=' * 80}\n")


def find_calls_to_crypto_functions(analyzer, binary):
    """Find all calls to crypto-related functions."""
    # Check if _CCCrypt symbol exists
    cccrypt_symbol = analyzer.callable_symbol_for_symbol_name("_CCCrypt")

    if not cccrypt_symbol:
        print("[-] _CCCrypt symbol not found in binary")
        return

    print(f"[+] Found _CCCrypt at address: {hex(cccrypt_symbol.address)}")

    # Get all calls to _CCCrypt
    encrypt_calls = analyzer.calls_to(cccrypt_symbol.address)

    if not encrypt_calls:
        print("[-] No calls to _CCCrypt found")
        return

    print(f"[+] Found {len(encrypt_calls)} call(s) to _CCCrypt\n")

    for call_idx, call in enumerate(encrypt_calls, 1):
        try:
            print(f"{'#' * 80}")
            print(f"# Call #{call_idx}")
            print(f"{'#' * 80}")

            # Get the function analyzer for the calling function
            funct = ObjcFunctionAnalyzer.get_function_analyzer(
                binary,
                call.caller_func_start_address
            )

            print(f"[*] Call from address: {hex(call.caller_addr)}")
            print(f"[*] Caller function starts at: {hex(call.caller_func_start_address)}")

            reg_contents = funct.get_register_contents_at_instruction(
                "x3",
                funct.get_instruction_at_address(call.caller_addr)
            )

            print(f"[*] x3 register contents: {reg_contents}")
            print(f"[*] x3 register type: {reg_contents.type}")

            if reg_contents.type == RegisterContentsType.IMMEDIATE:
                key_address = reg_contents.value
                print(f"\n[+] ✓ x3 contains IMMEDIATE value (static key address)")
                print(f"[+] Key pointer address: {hex(key_address)}")

                # Read 32 bytes for AES-256 key
                try:
                    key_bytes = binary.get_content_from_virtual_address(
                        VirtualMemoryPointer(key_address),
                        32
                    )

                    print(f"\n{'=' * 80}")
                    print(f"[+] STATIC KEY FOUND!")
                    print(f"{'=' * 80}")
                    print(f"Address: {hex(key_address)}")
                    print(f"Hex:     {key_bytes.hex()}")
                    print(f"Bytes:   [{', '.join(f'0x{b:02x}' for b in key_bytes)}]")

                    # Show hex dump
                    print(f"\nHex Dump:")
                    for i in range(0, 32, 16):
                        chunk = key_bytes[i:i + 16]
                        hex_str = ' '.join(f'{b:02x}' for b in chunk)
                        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                        print(f"  {hex(key_address + i)}: {hex_str:48s} | {ascii_str}")
                    print(f"{'=' * 80}")

                except Exception as e:
                    print(f"[-] Failed to read key bytes: {e}")

            else:
                print(f"\n[!] ⚠ x3 is NOT an immediate value")
                print(f"[!] Register type: {reg_contents.type}")
                print(f"[!] This might be a dynamic key (loaded from memory, computed, etc.)")
                print(f"\n[*] Showing disassembly to help identify key source...")

                # Show disassembly around the call
                disassemble_around_address(binary, call.caller_addr, 15, 5)

            print()

        except Exception as e:
            print(f"[-] Error analyzing function at {hex(call.caller_func_start_address)}: {e}")
            import traceback
            traceback.print_exc()
            print()

    return encrypt_calls


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print("Usage: python CryptoFind.py <path_to_macho_binary>")
        sys.exit(1)

    file_path = sys.argv[1]

    # Parse the binary and get the analyzer
    print(f"\n{'*' * 80}")
    print(f"Strongarm Crypto Key Finder")
    print(f"{'*' * 80}")
    print(f"[*] Parsing binary: {file_path}")
    analyzer, binary = parse_binary(file_path)
    print(f"[+] Analyzer created: {analyzer}")
    print(f"[+] Binary object: {binary}")
    print(f"{'*' * 80}\n")

    # Find crypto function calls
    print("[*] Searching for crypto function calls...")
    crypto_results = find_calls_to_crypto_functions(analyzer, binary)

    print(f"\n{'*' * 80}")
    print(f"Analysis Complete")
    print(f"{'*' * 80}")