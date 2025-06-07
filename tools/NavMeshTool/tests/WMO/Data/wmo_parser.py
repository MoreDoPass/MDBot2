"""
Parses a World of Warcraft Group WMO file (e.g., Blacktemple_000.wmo) for version 3.3.5a.
This script focuses on parsing the MOGP super-chunk and its sub-chunks containing geometry.
"""
import struct
import os

# --- I/O Helper Functions ---
def read_chunk_header(f):
    """Reads the 8-byte chunk header (ID and size)."""
    try:
        chunk_id_bytes = f.read(4)
        if len(chunk_id_bytes) < 4:
            return None, 0
        # Decode the chunk ID, reversing it from file order (e.g., REVM -> MVER)
        chunk_id = chunk_id_bytes.decode('ascii')[::-1]
        chunk_size = struct.unpack('<I', f.read(4))[0]
        return chunk_id, chunk_size
    except (struct.error, EOFError):
        return None, 0

def parse_wmo_group(filepath):
    """
    Parses a group WMO file, focusing on MVER, MOGP, and geometry chunks.
    """
    filename = os.path.basename(filepath)
    print(f"--- Parsing Group WMO File: {filename} ---")

    if not os.path.exists(filepath):
        print(f"Error: File not found at {filepath}")
        return None

    parsed_data = {
        'sub_chunks': {}
    }
    mogp_found = False

    try:
        with open(filepath, 'rb') as f:
            # 1. Parse MVER chunk
            chunk_id, chunk_size = read_chunk_header(f)
            if not chunk_id or chunk_id != 'MVER':
                print(f"Error: Expected MVER chunk, but found '{chunk_id}'.")
                return None
            
            if chunk_size >= 4:
                version = struct.unpack('<I', f.read(4))[0]
                print(f"Found chunk: 'MVER' with size {chunk_size}")
                print(f"  - WMO Version: {version}")
                if version != 17:
                    print(f"  !! WARNING: Expected version 17, got {version}.")
                parsed_data['MVER'] = {'version': version}
            
            # 2. Parse MOGP "super-chunk"
            mogp_chunk_id, mogp_chunk_size = read_chunk_header(f)
            if not mogp_chunk_id or mogp_chunk_id != 'MOGP':
                print(f"Error: Expected MOGP chunk, but found '{mogp_chunk_id}'.")
                return None

            print(f"Found chunk: 'MOGP' with size {mogp_chunk_size}")
            mogp_end_pos = f.tell() + mogp_chunk_size
            
            # --- MOGP Header ---
            mogp_header_size = 68
            if mogp_chunk_size < mogp_header_size:
                print(f"  - Error: MOGP super-chunk is too small ({mogp_chunk_size} bytes) to contain its header.")
                return None

            mogp_content = f.read(mogp_header_size)
            mogp_data_tuple = struct.unpack_from('<3I 6f 6H 4s 4I', mogp_content, 0)
            
            mogp_data = {
                'groupNameOffset': mogp_data_tuple[0],
                'descriptiveGroupNameOffset': mogp_data_tuple[1],
                'flags': f'{mogp_data_tuple[2]:08X}',
                'bbox_min': mogp_data_tuple[3:6],
                'bbox_max': mogp_data_tuple[6:9],
                'portal_start': mogp_data_tuple[9],
                'portal_count': mogp_data_tuple[10],
                'transBatchCount': mogp_data_tuple[11],
                'interiorBatchCount': mogp_data_tuple[12],
                'exteriorBatchCount': mogp_data_tuple[13],
                'padding_or_batch_type_d': mogp_data_tuple[14],
                'fogIds': list(mogp_data_tuple[15]),
                'liquid_type_or_flags': mogp_data_tuple[16],
                'wmo_group_id': mogp_data_tuple[17],
                'wotlk_flags2': mogp_data_tuple[18],
                'wotlk_unk_padding': mogp_data_tuple[19],
            }
            parsed_data['MOGP_Header'] = mogp_data
            mogp_found = True
            print("  - Parsed MOGP Header.")
            
            # --- MOGP Sub-chunks ---
            print("\n--- Parsing MOGP Sub-chunks ---")
            while f.tell() < mogp_end_pos:
                sub_chunk_id, sub_chunk_size = read_chunk_header(f)
                if not sub_chunk_id:
                    break

                next_chunk_pos = f.tell() + sub_chunk_size
                print(f"Found sub-chunk: '{sub_chunk_id}' with size {sub_chunk_size}")
                
                chunk_data = {}
                if sub_chunk_id == 'MOPY':
                    # SMOPoly: 2 bytes per polygon
                    num_polys = sub_chunk_size // 2
                    chunk_data['count'] = num_polys
                elif sub_chunk_id == 'MOVI':
                    # uint16_t per index
                    num_indices = sub_chunk_size // 2
                    chunk_data['count'] = num_indices
                elif sub_chunk_id == 'MOVT':
                    # C3Vector (3 floats, 12 bytes) per vertex position
                    # We only care about positions for now as parser combines them
                    num_vertices = sub_chunk_size // 12
                    chunk_data['count'] = num_vertices
                elif sub_chunk_id == 'MONR':
                    # C3Vector (3 floats, 12 bytes) per normal
                    num_normals = sub_chunk_size // 12
                    chunk_data['count'] = num_normals
                elif sub_chunk_id == 'MOTV':
                    # C2Vector (2 floats, 8 bytes) per tex coord
                    num_tex_coords = sub_chunk_size // 8
                    chunk_data['count'] = num_tex_coords
                elif sub_chunk_id == 'MOBA':
                     # We just need to acknowledge it for now
                    chunk_data['count'] = 'Not fully parsed'
                elif sub_chunk_id == 'MOBN':
                    # CAaBspNode: 16 bytes per node
                    num_nodes = sub_chunk_size // 16
                    chunk_data['count'] = num_nodes
                elif sub_chunk_id == 'MOBR':
                    # uint16_t per ref
                    num_refs = sub_chunk_size // 2
                    chunk_data['count'] = num_refs

                parsed_data['sub_chunks'][sub_chunk_id] = chunk_data
                f.seek(next_chunk_pos) # Move to the next sub-chunk

            print("\n--- Finished parsing group WMO file. ---")
            print("\n--- Geometry Summary ---")
            summary = {
                "Vertices (MOVT)": parsed_data.get('sub_chunks', {}).get('MOVT', {}).get('count', 0),
                "Indices (MOVI)": parsed_data.get('sub_chunks', {}).get('MOVI', {}).get('count', 0),
                "Triangles (from MOVI)": parsed_data.get('sub_chunks', {}).get('MOVI', {}).get('count', 0) // 3,
                "Polygons (MOPY)": parsed_data.get('sub_chunks', {}).get('MOPY', {}).get('count', 0),
                "BSP Nodes (MOBN)": parsed_data.get('sub_chunks', {}).get('MOBN', {}).get('count', 0),
                "BSP Refs (MOBR)": parsed_data.get('sub_chunks', {}).get('MOBR', {}).get('count', 0)
            }
            for key, value in summary.items():
                print(f"- {key}: {value}")

    except Exception as e:
        print(f"An unrecoverable error occurred: {e}")
        import traceback
        traceback.print_exc()

    return parsed_data


if __name__ == "__main__":
    # The script now targets a group WMO file.
    # You might need to adjust the path to a valid group file.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # --- IMPORTANT ---
    # CHANGE THIS to the group file you want to parse
    group_wmo_path = os.path.join(script_dir, "Blacktemple_048.wmo") 
    
    if not os.path.exists(group_wmo_path):
        print(f"!!! Test file not found: {group_wmo_path}")
        print("!!! Please download a WMO (like Black Temple) and place a group file")
        print("!!! (e.g., Blacktemple_000.wmo) in the same directory as this script.")
    else:
        parse_wmo_group(group_wmo_path)