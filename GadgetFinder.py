'''
This script analyzes executables to find specific instructions, like jmp esp (opcode FFE4), or SEH combinations in the code sections.

To use: Run the script from the command line:
- python GadgetFinder.py example.exe FFE4
- python GadgetFinder.py example.exe -SEH

Optional:
Use --loading-address 0x400000 to specify a loading address.
Add -SEH to search for SEH combinations instead of a specific code.
The script displays ASLR, DEP, and SafeSEH statuses, along with virtual addresses where it finds the specified code.
'''

import struct
import argparse

# Constants for offsets and sizes
DOS_HEADER_OFFSET = 0x3C
PE_HEADER_SIGNATURE = b'PE\x00\x00'
SECTION_HEADER_SIZE = 40
IMAGE_SCN_CNT_CODE = 0x00000020  # Section contains executable code

# SEH combinations
SEH_COMBINATIONS = {
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

def read_dword(f, offset):
    f.seek(offset)
    return struct.unpack('<I', f.read(4))[0]

def read_word(f, offset):
    f.seek(offset)
    return struct.unpack('<H', f.read(2))[0]

def parse_pe_header(f):
    pe_header_offset = read_dword(f, DOS_HEADER_OFFSET)
    f.seek(pe_header_offset)
    if f.read(4) != PE_HEADER_SIGNATURE:
        raise ValueError("Not a valid PE file.")
    num_of_sections = read_word(f, pe_header_offset + 6)
    optional_header_size = read_word(f, pe_header_offset + 20)
    optional_header_offset = pe_header_offset + 24
    magic = read_word(f, optional_header_offset)
    is_pe32_plus = (magic == 0x20B)
    
    if is_pe32_plus:
        dll_characteristics_offset = 78
        data_directory_offset = 112
    else:
        dll_characteristics_offset = 66
        data_directory_offset = 96

    return pe_header_offset, num_of_sections, optional_header_size, optional_header_offset, dll_characteristics_offset, data_directory_offset

def search_SEH_combinations(f, num_of_sections, section_headers_offset):
    results = []
    
    for i in range(num_of_sections):
        section_offset = section_headers_offset + (i * SECTION_HEADER_SIZE)
        characteristics = read_dword(f, section_offset + 36)
        
        if characteristics & IMAGE_SCN_CNT_CODE:
            virtual_address = read_dword(f, section_offset + 12)
            raw_data_offset = read_dword(f, section_offset + 20)
            raw_data_size = read_dword(f, section_offset + 16)
            f.seek(raw_data_offset)
            section_data = f.read(raw_data_size)
            
            for comb_hex, comb_desc in SEH_COMBINATIONS.items():
                comb_bytes = bytes.fromhex(comb_hex)
                comb_length = len(comb_bytes)
                
                for j in range(len(section_data) - comb_length + 1):
                    if section_data[j:j + comb_length] == comb_bytes:
                        va_offset = virtual_address + j
                        results.append((va_offset, comb_desc))
    
    return results

def search_binary_code(f, num_of_sections, section_headers_offset, binary_code_bytes):
    binary_code_length = len(binary_code_bytes)
    jmp_esp_offsets = []

    for i in range(num_of_sections):
        section_offset = section_headers_offset + (i * SECTION_HEADER_SIZE)
        characteristics = read_dword(f, section_offset + 36)
        
        if characteristics & IMAGE_SCN_CNT_CODE:
            virtual_address = read_dword(f, section_offset + 12)
            raw_data_offset = read_dword(f, section_offset + 20)
            raw_data_size = read_dword(f, section_offset + 16)
            f.seek(raw_data_offset)
            section_data = f.read(raw_data_size)
            
            for j in range(len(section_data) - binary_code_length + 1):
                if section_data[j:j + binary_code_length] == binary_code_bytes:
                    va_offset = virtual_address + j
                    jmp_esp_offsets.append(va_offset)
    
    return jmp_esp_offsets

def check_aslr(dll_characteristics):
    return dll_characteristics & 0x0040 != 0

def check_dep(dll_characteristics):
    return dll_characteristics & 0x0100 != 0

def check_safeseh(data_directory_offset, f):
    f.seek(data_directory_offset + 128)
    return read_dword(f, data_directory_offset + 128) != 0

def main():
    parser = argparse.ArgumentParser(description='Search for SEH combinations or binary code in an executable.')
    parser.add_argument('executable', help='Path to the executable file')
    parser.add_argument('binary_code', nargs='?', default=None, help='Binary code to search for (in hex format, e.g., "FFE4" for JMP ESP)')
    parser.add_argument('-SEH', action='store_true', help='Search for specific combinations of instructions (SEH)')
    parser.add_argument('--loading-address', type=lambda x: int(x, 16), default=0x00000000, help='Loading address of the executable (optional, in hexadecimal)') 
    
    args = parser.parse_args()
    
    if not args.binary_code and not args.SEH:
        parser.error('Either binary_code or -SEH must be specified.')
    
    binary_code_bytes = bytes.fromhex(args.binary_code) if args.binary_code else None
    loading_address = args.loading_address
    
    with open(args.executable, 'rb') as f:
        pe_header_offset, num_of_sections, optional_header_size, optional_header_offset, dll_characteristics_offset, data_directory_offset = parse_pe_header(f)
        section_headers_offset = optional_header_offset + optional_header_size
        
        dll_characteristics = read_word(f, optional_header_offset + dll_characteristics_offset)
        aslr_enabled = check_aslr(dll_characteristics)
        dep_enabled = check_dep(dll_characteristics)
        safeseh_enabled = check_safeseh(data_directory_offset, f)
        
        print(f"ASLR: {'Enabled' if aslr_enabled else 'Disabled'}")
        print(f"DEP: {'Enabled' if dep_enabled else 'Disabled'}")
        print(f"SafeSEH: {'Enabled' if safeseh_enabled else 'Disabled'}")
        
        if binary_code_bytes:
            jmp_esp_offsets = search_binary_code(f, num_of_sections, section_headers_offset, binary_code_bytes)
            for va_offset in jmp_esp_offsets:
                print(f"Binary code found at virtual address: 0x{va_offset + loading_address:08X}")
        
        if args.SEH:
            SEH_results = search_SEH_combinations(f, num_of_sections, section_headers_offset)
            for va_offset, desc in SEH_results:
                print(f"{desc} found at virtual address: 0x{va_offset + loading_address:08X}")

if __name__ == "__main__":
    main()
