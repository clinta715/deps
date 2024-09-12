import pefile
import sys

def get_dll_dependencies(exe_path):
    try:
        pe = pefile.PE(exe_path)
        
        # Get the import directory
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"DLL: {entry.dll.decode()}")
                for imp in entry.imports:
                    print(f"  Function: {imp.name.decode() if imp.name else 'Ordinal'} ({imp.ordinal})")
        else:
            print("No import directory found.")
        
        pe.close()
    except pefile.PEFormatError:
        print(f"Error: {exe_path} is not a valid PE file")
    except FileNotFoundError:
        print(f"Error: File {exe_path} not found")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_exe>")
    else:
        exe_path = sys.argv[1]
        get_dll_dependencies(exe_path)