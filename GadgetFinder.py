#!/usr/bin/env python3
"""
GadgetFinder: A tool to analyze PE executables for specific instructions or SEH combinations.

Usage:
    python GadgetFinder.py example.exe FFE4
    python GadgetFinder.py example.exe -SEH
    python GadgetFinder.py example.exe FFE4 --loading-address 0x400000
"""

import struct
import argparse
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass

# PE Format Constants
DOS_HEADER_OFFSET = 0x3C
PE_SIGNATURE = b'PE\x00\x00'
SECTION_HEADER_SIZE = 40
IMAGE_SCN_CNT_CODE = 0x20  # Section contains executable code

@dataclass
class PEHeaderInfo:
    """Stores parsed PE header information"""
    offset: int
    num_sections: int
    opt_header_size: int
    opt_header_offset: int
    dll_char_offset: int
    data_dir_offset: int

class GadgetFinder:
    """Main class for analyzing PE executables"""
    
    SEH_COMBINATIONS: Dict[str, str] = {
            "58 58 C3": "pop eax; pop eax; ret",
    "58 5B C3": "pop eax; pop ebx; ret",
    "58 59 C3": "pop eax; pop ecx; ret",
    "58 5A C3": "pop eax; pop edx; ret",
    "58 5E C3": "pop eax; pop esi; ret",
    "58 5F C3": "pop eax; pop edi; ret",
    "58 5D C3": "pop eax; pop ebp; ret",
    "5B 58 C3": "pop ebx; pop eax; ret",
    "5B 5B C3": "pop ebx; pop ebx; ret",
    "5B 59 C3": "pop ebx; pop ecx; ret",
    "5B 5A C3": "pop ebx; pop edx; ret",
    "5B 5E C3": "pop ebx; pop esi; ret",
    "5B 5F C3": "pop ebx; pop edi; ret",
    "5B 5D C3": "pop ebx; pop ebp; ret",
    "59 58 C3": "pop ecx; pop eax; ret",
    "59 5B C3": "pop ecx; pop ebx; ret",
    "59 59 C3": "pop ecx; pop ecx; ret",
    "59 5A C3": "pop ecx; pop edx; ret",
    "59 5E C3": "pop ecx; pop esi; ret",
    "59 5F C3": "pop ecx; pop edi; ret",
    "59 5D C3": "pop ecx; pop ebp; ret",
    "5A 58 C3": "pop edx; pop eax; ret",
    "5A 5B C3": "pop edx; pop ebx; ret",
    "5A 59 C3": "pop edx; pop ecx; ret",
    "5A 5A C3": "pop edx; pop edx; ret",
    "5A 5E C3": "pop edx; pop esi; ret",
    "5A 5F C3": "pop edx; pop edi; ret",
    "5A 5D C3": "pop edx; pop ebp; ret",
    "5E 58 C3": "pop esi; pop eax; ret",
    "5E 5B C3": "pop esi; pop ebx; ret",
    "5E 59 C3": "pop esi; pop ecx; ret",
    "5E 5A C3": "pop esi; pop edx; ret",
    "5E 5E C3": "pop esi; pop esi; ret",
    "5E 5F C3": "pop esi; pop edi; ret",
    "5E 5D C3": "pop esi; pop ebp; ret",
    "5F 58 C3": "pop edi; pop eax; ret",
    "5F 5B C3": "pop edi; pop ebx; ret",
    "5F 59 C3": "pop edi; pop ecx; ret",
    "5F 5A C3": "pop edi; pop edx; ret",
    "5F 5E C3": "pop edi; pop esi; ret",
    "5F 5F C3": "pop edi; pop edi; ret",
    "5F 5D C3": "pop edi; pop ebp; ret",
    "5D 58 C3": "pop ebp; pop eax; ret",
    "5D 5B C3": "pop ebp; pop ebx; ret",
    "5D 59 C3": "pop ebp; pop ecx; ret",
    "5D 5A C3": "pop ebp; pop edx; ret",
    "5D 5E C3": "pop ebp; pop esi; ret",
    "5D 5F C3": "pop ebp; pop edi; ret",
    "5D 5D C3": "pop ebp; pop ebp; ret",
    }

    def __init__(self, filename: str, loading_address: int = 0):
        self.filename = filename
        self.loading_address = loading_address
        self.file_data = self._load_file()

    def _load_file(self) -> bytes:
        """Load the entire file into memory"""
        try:
            with open(self.filename, 'rb') as f:
                return f.read()
        except (IOError, OSError) as e:
            raise ValueError(f"Failed to read file {self.filename}: {e}")

    def _read_dword(self, offset: int) -> int:
        """Read a 4-byte unsigned integer from offset"""
        return struct.unpack('<I', self.file_data[offset:offset+4])[0]

    def _read_word(self, offset: int) -> int:
        """Read a 2-byte unsigned integer from offset"""
        return struct.unpack('<H', self.file_data[offset:offset+2])[0]

    def parse_pe_header(self) -> PEHeaderInfo:
        """Parse the PE header and return relevant offsets"""
        pe_offset = self._read_dword(DOS_HEADER_OFFSET)
        if self.file_data[pe_offset:pe_offset+4] != PE_SIGNATURE:
            raise ValueError("Not a valid PE file")

        num_sections = self._read_word(pe_offset + 6)
        opt_header_size = self._read_word(pe_offset + 20)
        opt_header_offset = pe_offset + 24
        magic = self._read_word(opt_header_offset)
        
        is_pe32_plus = (magic == 0x20B)
        dll_char_offset = 78 if is_pe32_plus else 66
        data_dir_offset = 112 if is_pe32_plus else 96

        return PEHeaderInfo(pe_offset, num_sections, opt_header_size,
                          opt_header_offset, dll_char_offset, data_dir_offset)

    def get_security_features(self, header: PEHeaderInfo) -> Tuple[bool, bool, bool]:
        """Check ASLR, DEP, and SafeSEH status"""
        dll_chars = self._read_word(header.opt_header_offset + header.dll_char_offset)
        aslr = bool(dll_chars & 0x0040)
        dep = bool(dll_chars & 0x0100)
        safeseh = self._read_dword(header.data_dir_offset + 128) != 0
        return aslr, dep, safeseh

    def search_gadgets(self, header: PEHeaderInfo, 
                      binary_code: Optional[bytes] = None) -> List[Tuple[int, str]]:
        """Search for specific binary code or SEH combinations"""
        results = []
        section_offset = header.opt_header_offset + header.opt_header_size
        
        for i in range(header.num_sections):
            offset = section_offset + (i * SECTION_HEADER_SIZE)
            if self._read_dword(offset + 36) & IMAGE_SCN_CNT_CODE:
                va = self._read_dword(offset + 12)
                raw_offset = self._read_dword(offset + 20)
                raw_size = self._read_dword(offset + 16)
                section_data = self.file_data[raw_offset:raw_offset + raw_size]

                if binary_code:
                    results.extend(self._search_binary(section_data, va, binary_code))
                else:
                    results.extend(self._search_seh(section_data, va))

        return results

    def _search_binary(self, data: bytes, va: int, code: bytes) -> List[Tuple[int, str]]:
        """Search for specific binary code in section data"""
        results = []
        code_len = len(code)
        for i in range(len(data) - code_len + 1):
            if data[i:i + code_len] == code:
                results.append((va + i + self.loading_address, f"Found at 0x{va + i:08x}"))
        return results

    def _search_seh(self, data: bytes, va: int) -> List[Tuple[int, str]]:
        """Search for SEH combinations in section data"""
        results = []
        for hex_code, desc in self.SEH_COMBINATIONS.items():
            code_bytes = bytes.fromhex(hex_code)
            code_len = len(code_bytes)
            for i in range(len(data) - code_len + 1):
                if data[i:i + code_len] == code_bytes:
                    results.append((va + i + self.loading_address, desc))
        return results

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('executable', help='Path to the executable file')
    parser.add_argument('binary_code', nargs='?', help='Binary code to search (hex, e.g., "FFE4")')
    parser.add_argument('-SEH', action='store_true', help='Search for SEH combinations')
    parser.add_argument('--loading-address', type=lambda x: int(x, 16), 
                       default=0, help='Loading address (hex)')
    
    args = parser.parse_args()
    if not (args.binary_code or args.SEH):
        parser.error('Either binary_code or -SEH must be specified')

    try:
        finder = GadgetFinder(args.executable, args.loading_address)
        header = finder.parse_pe_header()
        aslr, dep, safeseh = finder.get_security_features(header)
        
        print(f"ASLR: {'Enabled' if aslr else 'Disabled'}")
        print(f"DEP: {'Enabled' if dep else 'Disabled'}")
        print(f"SafeSEH: {'Enabled' if safeseh else 'Disabled'}")
        
        binary_code = bytes.fromhex(args.binary_code) if args.binary_code else None
        results = finder.search_gadgets(header, binary_code)
        
        for address, desc in results:
            print(f"{desc}: 0x{address:08x}")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
