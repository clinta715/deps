import pefile
import sys
import datetime

def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        
        print(f"Analysis of {file_path}:")
        
        # Basic file information
        print("\n1. Basic Information:")
        print(f"Machine: {pe.FILE_HEADER.Machine}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"Time Date Stamp: {datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)}")
        
        # Sections
        print("\n2. Sections:")
        for section in pe.sections:
            print(f"  {section.Name.decode().rstrip('\x00')}: Virtual Address: {hex(section.VirtualAddress)}, Size: {section.SizeOfRawData}")
        
        # Imports (DLL dependencies)
        print("\n3. Imports (DLL Dependencies):")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"  DLL: {entry.dll.decode()}")
                for imp in entry.imports[:5]:  # Limit to first 5 imports for brevity
                    print(f"    Function: {imp.name.decode() if imp.name else 'Ordinal'} ({imp.ordinal})")
                if len(entry.imports) > 5:
                    print("    ...")
        
        # Exports
        print("\n4. Exports:")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(f"  {exp.name.decode() if exp.name else ''} at {hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)}")
        
        # Resources
        print("\n5. Resources:")
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                print(f"  Type: {pefile.RESOURCE_TYPE.get(resource_type.struct.Id, resource_type.struct.Id)}")
        
        # Security
        print("\n6. Security:")
        if hasattr(pe, 'OPTIONAL_HEADER'):
            print(f"  DEP: {'Yes' if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100 else 'No'}")
            print(f"  ASLR: {'Yes' if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040 else 'No'}")
        
        pe.close()
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_pe_file>")
    else:
        file_path = sys.argv[1]
        analyze_pe_file(file_path)