"""
Finds all file dependencies for a World of Warcraft Root WMO file for version 3.3.5a.
This script parses a given root .wmo file and extracts all referenced
texture files (.BLP), model files (.M2), and derives the names of
all required group .wmo files.
"""
import struct
import os
import argparse

def read_chunk_header(f):
    """Reads the 8-byte chunk header (ID and size)."""
    try:
        header_bytes = f.read(8)
        if len(header_bytes) < 8:
            return None, 0
        # Chunks are stored as reversed chars (e.g., 'MVER' is 'REVM')
        chunk_id_bytes, chunk_size = struct.unpack('<4sI', header_bytes)
        chunk_id = chunk_id_bytes.decode('ascii')[::-1]
        return chunk_id, chunk_size
    except (struct.error, EOFError):
        return None, 0

def parse_string_blob(data):
    """Parses a blob of null-terminated strings from a byte array."""
    if not data:
        return []
    return [s.decode('utf-8', errors='ignore') for s in data.split(b'\0') if s]

def find_wmo_dependencies(root_wmo_path):
    """
    Parses a root WMO file to find all unique file dependencies
    (textures, M2 models, group WMOs, and skybox).
    """
    if not os.path.exists(root_wmo_path):
        print(f"Error: Root WMO file not found at {root_wmo_path}")
        return None

    print(f"--- Parsing Root WMO File: {os.path.basename(root_wmo_path)} ---")
    
    dependencies = set()
    n_groups = 0

    with open(root_wmo_path, 'rb') as f:
        file_size = os.fstat(f.fileno()).st_size
        
        while f.tell() < file_size:
            chunk_data_pos = f.tell()
            chunk_id, chunk_size = read_chunk_header(f)
            
            if not chunk_id:
                print("Reached end of file or read error.")
                break

            # Calculate where the next chunk should start
            next_chunk_pos = f.tell() + chunk_size
            
            # Ensure we don't read past the end of the file if chunk_size is corrupted
            if next_chunk_pos > file_size:
                print(f"Warning: Chunk '{chunk_id}' with size {chunk_size} exceeds file boundary. Stopping parse.")
                break

            if chunk_size > 0:
                chunk_data = f.read(chunk_size)
            else:
                chunk_data = b''

            if chunk_id == 'MOHD':
                if chunk_size >= 8:
                    n_groups = struct.unpack_from('<I', chunk_data, 4)[0]
                    print(f"Found MOHD chunk: model has {n_groups} groups.")
            elif chunk_id == 'MOTX':
                textures = parse_string_blob(chunk_data)
                dependencies.update(textures)
                print(f"Found MOTX chunk: Found {len(textures)} texture paths.")
            elif chunk_id == 'MODN':
                doodads = parse_string_blob(chunk_data)
                dependencies.update(doodads)
                print(f"Found MODN chunk: Found {len(doodads)} M2 model paths.")
            elif chunk_id == 'MOSB':
                if chunk_size > 0:
                    skybox_path = chunk_data.split(b'\0', 1)[0].decode('utf-8', errors='ignore').strip()
                    if skybox_path:
                        dependencies.add(skybox_path)
                        print(f"Found MOSB chunk: Found skybox '{skybox_path}'.")
            
            # Ensure we're at the right place for the next iteration.
            f.seek(next_chunk_pos)
            
    # Add group WMO files to dependencies
    if n_groups > 0:
        base_path = root_wmo_path.rsplit('.wmo', 1)[0]
        base_name = os.path.basename(base_path)
        for i in range(n_groups):
            # WoW file paths use backslashes.
            group_filename = f"{base_name}_{i:03d}.wmo"
            dependencies.add(group_filename)
        print(f"Added {n_groups} group WMO file paths to dependency list.")
    
    return dependencies

def main():
    parser = argparse.ArgumentParser(
        description="Parses a World of Warcraft Root WMO file (v3.3.5a) and lists all its file dependencies (other WMOs, M2s, BLPs)."
    )
    parser.add_argument(
        "root_wmo_file",
        help="Path to the root WMO file (e.g., 'Data/Blacktemple.wmo')."
    )
    args = parser.parse_args()

    dependencies = find_wmo_dependencies(args.root_wmo_file)

    if dependencies is not None:
        print("\n--- Essential Geometry Dependencies (WMO, M2/MDX) ---")
        if dependencies:
            # Filter for essential geometry files and sort for consistent output
            essential_files = []
            for dep in sorted(list(dependencies)):
                lower_dep = dep.lower()
                if lower_dep.endswith(('.wmo', '.m2', '.mdx')):
                    essential_files.append(dep)

            # Print the essential files using WoW's path separator
            for dep in essential_files:
                print(dep.replace('/', '\\'))

            print(f"\nTotal unique files found: {len(dependencies)}")
            print(f"Essential geometry files listed: {len(essential_files)}")
            print("NOTE: Texture files (.BLP) were omitted from this list as they are not required for NavMesh generation.")
        else:
            print("No dependencies found.")

if __name__ == "__main__":
    # Example usage from command line:
    # python wmo_parser.py "path/to/Blacktemple.wmo"
    #
    # To run from an IDE, you might need to configure the script argument.
    # As a fallback for simple execution without args, we can hardcode a path.
    import sys
    if len(sys.argv) == 1:
        # No command line arguments provided, use a default path for convenience.
        # This makes it easier to run from inside an IDE like VSCode.
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default_file = os.path.join(script_dir, "Blacktemple.wmo") # CHANGE THIS if needed
        
        # Check if the default file exists before trying to use it
        if os.path.exists(default_file):
            print("No file provided via command line, attempting to use default:")
            print(f"> python {os.path.basename(__file__)} \"{default_file}\"")
            sys.argv.append(default_file)
        else:
            print("No file provided via command line, and the default file was not found.")
            print(f"Default path checked: {default_file}")
            print("\nPlease run the script with a path to a root WMO file, for example:")
            print(f"> python {os.path.basename(__file__)} \"World\\wmo\\KhazModan\\Cities\\Ironforge\\ironforge.wmo\"")

    main()