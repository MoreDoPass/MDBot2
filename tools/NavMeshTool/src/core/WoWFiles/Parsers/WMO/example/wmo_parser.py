"""Parses and visualizes World of Warcraft WMO (World Map Object) group files
for version 3.3.5a (WotLK).

This script focuses on extracting 3D geometry data from WMO group files
(e.g., _000.wmo, _001.wmo, etc.). It can process individual group files or
aggregate data from multiple group files matching a pattern.

Key WMO Chunks Processed for Geometry:
- MVER: File version (expected to be 17).
- MOGP: The main super-chunk in group files, containing a header and sub-chunks.
    - MOGP Header: Contains flags, bounding box, portal info, and other metadata
                   for the group.
    - MOVT (Vertices): Contains vertex data. For group files, this script assumes
                       it primarily holds 3D position coordinates (3 floats, 12 bytes).
                       Normals and texture coordinates are expected in MONR/MOTV.
    - MOVI (Vertex Indices): Contains indices that define triangles from MOVT vertices.
    - MOPY (Polygon/Material Info): Contains flags for each triangle (e.g., walkability)
                                    and material IDs. These flags are crucial for
                                    NavMesh generation.
    - MOBN (Collision BSP Nodes): Defines the nodes of a BSP tree for collision.
    - MOBR (Collision BSP References): Contains indices into MOVI, referencing
                                       triangles that form the collision geometry
                                       as defined by MOBN leaf nodes.
    - MONR (Normals): Vertex normals, if not part of MOVT.
    - MOTV (Texture Coordinates): Vertex texture coordinates.
    - MOCV (Vertex Colors): Vertex color data.
    - MLIQ (Liquid Data): Information about liquids within the group.
    - MODR (Doodad References): References to doodads specific to this group.


Data for NavMesh Generation:
The script extracts data vital for NavMesh construction:
1.  Visual Geometry: Vertices from MOVT and triangle indices from MOVI.
2.  Collision Geometry: Vertices from MOVT, but triangles are selected based on
    the MOBN (BSP nodes) and MOBR (triangle references from MOVI) chunks.
3.  Polygon Flags: From MOPY, these flags (e.g., F_WALKABLE, F_UNWALKABLE)
    determine which surfaces are traversable.

Visualization:
- PyVista is used for 3D visualization of the extracted geometry.
- Coordinates are typically normalized to the [-1, 1] range for stable camera operation.
- Functions are provided to:
    - Visualize a single WMO group file (either its visual or collision geometry).
    - Aggregate and visualize geometry (visual or collision) from multiple WMO
      group files. This "blind" aggregation does not account for individual
      group transformations; for that, the root WMO file would be needed.

Usage as a C++ Reference:
This script, along with the accompanying README.md, serves as a practical
reference for understanding the WMO group file structure and for developing
a C++ parser. The parsing functions (read_uint32, parse_mogp_header, etc.)
and geometry extraction logic (get_visual_geometry, get_collision_geometry)
demonstrate how to interpret the binary data and extract meaningful information.

Note on Coordinate Systems:
The geometry within WMO group files is in a local coordinate system relative
to the WMO's origin. To place these groups correctly in the game world,
transformation data from the root WMO file (specifically the MOGI chunk) and
potentially from ADT files (if the WMO is placed on a map tile) is required.
This script currently does not parse the root WMO for these transformations
when aggregating multiple groups.
"""
import struct
import os
import glob
import numpy as np
import pyvista as pv
# import csv # Убран импорт CSV

# Helper functions to read data types (Little Endian)
def read_bytes(f, num_bytes):
    return f.read(num_bytes)

def read_uint32(f):
    return struct.unpack('<I', f.read(4))[0]

def read_int32(f):
    return struct.unpack('<i', f.read(4))[0]

def read_uint16(f):
    return struct.unpack('<H', f.read(2))[0]

def read_int16(f):
    return struct.unpack('<h', f.read(2))[0]
    
def read_uint8(f):
    return struct.unpack('<B', f.read(1))[0]

def read_float(f):
    return struct.unpack('<f', f.read(4))[0]

def read_vec3(f):
    return struct.unpack('<fff', f.read(12))

def read_chunk_header(f):
    try:
        chunk_id_bytes = f.read(4)
        if not chunk_id_bytes or len(chunk_id_bytes) < 4:
            return None, 0
        chunk_id = chunk_id_bytes.decode('ascii')[::-1]
        chunk_size = read_uint32(f)
        return chunk_id, chunk_size
    except EOFError:
        return None, 0
    except struct.error:
        return None, 0

def parse_mver(f, size, filename=""):
    version = read_uint32(f)
    print(f"  MVER Chunk (in {filename}): Version = {version}")
    if version != 17:
        print(f"    Warning: Expected WMO version 17, got {version}")
    return {"version": version}

def parse_mogp_header(f, filename=""):
    print(f"  MOGP Header (in {filename}):")
    header = {}
    header['groupNameOffset'] = read_uint32(f) # Points to a name in MOGN in the root WMO
    header['descriptiveGroupNameOffset'] = read_uint32(f) # Points to a name in MOGN in the root WMO
    header['flags'] = read_uint32(f)
    
    # Bounding box (local to this group)
    header['bounding_box_min'] = read_vec3(f)
    header['bounding_box_max'] = read_vec3(f)
    
    header['portal_start_index'] = read_uint16(f) # Index into MOPR chunk
    header['portal_count'] = read_uint16(f)
    
    header['transBatchCount'] = read_uint16(f)  # Batches using MobaMaterialType_Transparent
    header['interiorBatchCount'] = read_uint16(f) # Batches using MobaMaterialType_Interior
    header['exteriorBatchCount'] = read_uint16(f) # Batches using MobaMaterialType_Exterior
    header['padding_or_batch_type_d'] = read_uint16(f) # Might be count for MobaMaterialType_ExteriorLit
    
    header['fogIds'] = [read_uint8(f) for _ in range(4)] # Index into MFOG chunk
    header['liquid_type_or_flags'] = read_uint32(f) # Based on MLIQ chunk. Wowdev.wiki says "flags"
    header['wmo_group_id'] = read_uint32(f) # Referenced by group names in MOGN in root WMO
    header['wotlk_flags2'] = read_uint32(f) # Added in WotLK
    header['wotlk_unk_padding'] = read_uint32(f) # Added in WotLK, mostly 0

    print(f"    Flags: {header['flags']:08X}")
    print(f"    BoundingBoxMin (local): {header['bounding_box_min']}")
    print(f"    BoundingBoxMax (local): {header['bounding_box_max']}")
    print(f"    PortalStartIndex: {header['portal_start_index']}, PortalCount: {header['portal_count']}")
    print(f"    LiquidType/Flags: {header['liquid_type_or_flags']}")
    print(f"    WMO Group ID: {header['wmo_group_id']}")
    # Note: True position/orientation of this group is in the Root WMO's MOGI chunk for this group ID.
    return header

def parse_mopy(f, size):
    # print(f"    MOPY Chunk (Material Info / Polygon Flags - Size: {size} bytes):")
    num_polys = size // 2
    polys = []
    for i in range(num_polys):
        flags = read_uint8(f)
        material_id = read_uint8(f) # Index into MOMT (materials) in root WMO
        polys.append({'flags': flags, 'material_id': material_id})
    # print(f"      Total MOPY entries (triangles): {num_polys}")
    return polys

def parse_movi(f, size):
    # print(f"    MOVI Chunk (Vertex Indices - Size: {size} bytes):")
    num_indices = size // 2
    indices = [read_uint16(f) for _ in range(num_indices)]
    # print(f"      Total vertex indices read: {num_indices} (implies {num_indices // 3} triangles)")
    # if indices:
    #     print(f"      Min index value in MOVI: {min(indices)}, Max index value in MOVI: {max(indices)}")
    return indices

def parse_movt(f, size):
    # print(f"    MOVT Chunk (Vertices - Size: {size} bytes):")
    vertex_size = 12 # Only 3*float for position, normals and texcoords are in other chunks or root file
    # According to wowdev.wiki, MOVT in group files is ONLY vertex positions (3 floats).
    # Normals (MONR), TexCoords (MOTV), VertexColors (MOCV) are separate.
    # Our previous assumption of 32 bytes (pos, norm, tex) might be for root file or a misunderstanding.
    # Let's try with 12 bytes for a group file.
    
    # Re-evaluating based on common WMO structure for groups:
    # MOVT: Vertex positions (Vector3f[nVertices]) - size = nVertices * 12
    # MONR: Vertex normals (Vector3f[nNormals]) - size = nNormals * 12
    # MOTV: Texture coordinates (Vector2f[nTexCoords]) - size = nTexCoords * 8

    # The MOVT in group file seems to be just Vector3f (12 bytes)
    num_vertices = size // 12 
    vertices_data = []
    for i in range(num_vertices):
        pos = read_vec3(f)
        # For group files, norm and tex are often in MONR and MOTV or from root WMO's materials
        vertices_data.append({'pos': pos, 'norm': (0,0,0), 'tex': (0,0)}) # Placeholder norm/tex
    # print(f"      Total vertices read (assuming 12 bytes/vertex): {num_vertices}")
    
    if size % 12 != 0:
        padding = size % 12
        # print(f"      Warning: MOVT size {size} not perfectly divisible by 12. Remainder: {padding} bytes. Reading padding.")
        f.read(padding) # Read and discard padding
    return vertices_data


def parse_monr(f, size): # Vertex Normals
    # print(f"    MONR Chunk (Normals - Size: {size} bytes).")
    num_normals = size // 12 # Vector3f
    normals = [read_vec3(f) for _ in range(num_normals)]
    # print(f"      Read {len(normals)} normals.")
    return normals

def parse_motv(f, size): # Texture Coordinates
    # print(f"    MOTV Chunk (Texture Coordinates - Size: {size} bytes).")
    num_tex_coords = size // 8 # Vector2f
    tex_coords = [struct.unpack('<ff', f.read(8)) for _ in range(num_tex_coords)]
    # print(f"      Read {len(tex_coords)} texture coordinates.")
    return tex_coords
    
def parse_moba(f,size): # Render Batches
    # print(f"    MOBA Chunk (Render Batches - Size: {size} bytes).")
    # This defines how to render parts of the mesh, using materials, texcoords etc.
    # For just getting geometry, we might not need to parse its internals deeply.
    # For now, we'll skip the complex structure.
    # Structure is roughly:
    # uint16_t unknown_or_flags; // usually 0x4000, indicates tex_coords from MOTV_chunk?
    # uint16_t material_id_plus_blend_mode; // first byte material_id (index into MOMT), second byte blend_mode
    # uint16_t start_index_plus_flags;      // first byte start_index_in_MOTV_tex_coords, second byte some_flags (related to tex wrapping?)
    # uint16_t num_tex_coords;
    # uint16_t start_vertex; // Index into MOVT
    # uint16_t end_vertex;   // Index into MOVT
    # uint16_t start_triangle; // Index into MOVI * 3 (actual index)
    # uint16_t num_triangles;
    f.seek(size, os.SEEK_CUR) 
    return {"data_size": size, "parsed": False, "info": "Skipped internal MOBA parsing"}


def parse_mocv(f, size): # Vertex Colors (CVec4UByte)
    # print(f"    MOCV Chunk (Vertex Colors - Size: {size} bytes).")
    num_colors = size // 4 # BGRA, 1 byte per channel
    colors = [f.read(4) for _ in range(num_colors)] # Keep as bytes for now
    # print(f"      Read {len(colors)} vertex colors.")
    return colors

def parse_mliq_header(f):
    header = {}
    header['xverts'] = read_int32(f)
    header['yverts'] = read_int32(f)
    header['xtiles'] = read_int32(f)
    header['ytiles'] = read_int32(f)
    header['liquid_corner'] = read_vec3(f)
    header['liquid_mtl_id'] = read_uint16(f)
    return header

def parse_mliq(f, size):
    # print(f"    MLIQ Chunk (Liquid Data - Size: {size} bytes).")
    # For now, just parse header and skip rest if not needed for basic geometry
    parsed_mliq = {}
    start_pos = f.tell()
    header_size = 26 # Size of MLIQ_Header struct
    if size >= header_size:
        parsed_mliq['header'] = parse_mliq_header(f)
        remaining_size = size - (f.tell() - start_pos)
        if remaining_size > 0:
            # print(f"      Skipping {remaining_size} bytes of MLIQ vertex/tile data.")
            f.seek(remaining_size, os.SEEK_CUR)
    else:
        # print(f"      MLIQ chunk too small ({size} bytes) to parse header. Skipping.")
        f.seek(size, os.SEEK_CUR)
        parsed_mliq['error'] = "Chunk too small for header"
    
    return parsed_mliq


def parse_mobn(f, size): # Collision BSP Nodes
    # print(f"    MOBN Chunk (Collision BSP Nodes - Size: {size} bytes):")
    node_size = 16 
    num_nodes = size // node_size
    nodes = []
    for i in range(num_nodes):
        entry = {}
        entry['flags'] = read_uint16(f)
        entry['negChild'] = read_int16(f)
        entry['posChild'] = read_int16(f)
        entry['nFaces'] = read_uint16(f)
        entry['faceStart'] = read_uint32(f) # Index into MOBR
        entry['planeDist'] = read_float(f)
        nodes.append(entry)
    # print(f"      Total MOBN nodes: {num_nodes}")
    if size % node_size != 0:
        # print(f"      Warning: MOBN size {size} not perfectly divisible by node_size {node_size}. Padding?")
        f.read(size % node_size)
    return nodes

def parse_mobr(f, size): # Collision BSP References to MOVI triangles
    # print(f"    MOBR Chunk (Collision BSP References - Size: {size} bytes):")
    num_refs = size // 2 
    refs = [read_uint16(f) for _ in range(num_refs)] # These are indices into the MOVI-defined triangle list
    # print(f"      Total MOBR references: {num_refs}")
    if size % 2 != 0:
         # print(f"     Warning: MOBR size {size} is odd. Padding?")
         f.read(size % 2)
    return refs

def parse_modr(f, size): # Doodad References for this group
    # print(f"    MODR Chunk (Doodad References - Size: {size} bytes).")
    # Each entry is an index into the main WMO's MODD (Doodad Definitions) chunk
    num_refs = size // 4 # uint32_t per ref
    refs = [read_uint32(f) for _ in range(num_refs)]
    # print(f"      Read {len(refs)} doodad instance references.")
    return refs
    
def skip_chunk_data(f, size, chunk_id):
    # print(f"    Skipping {chunk_id} Chunk (Size: {size} bytes) in group file.")
    f.seek(size, os.SEEK_CUR)
    return None

def parse_wmo_group(filepath):
    print(f"\\nParsing WMO Group File: {filepath}")
    filename = os.path.basename(filepath)
    parsed_group_data = {'filename': filename}

    try:
        with open(filepath, 'rb') as f:
            chunk_id, chunk_size = read_chunk_header(f)
            if chunk_id == "MVER":
                parsed_group_data['MVER'] = parse_mver(f, chunk_size, filename)
            else:
                print(f"  Error: Expected MVER chunk first, got {chunk_id}. Aborting for {filename}.")
                return None

            chunk_id, chunk_size = read_chunk_header(f)
            if chunk_id == "MOGP":
                # print(f"  Found MOGP Super-Chunk (Size: {chunk_size}) in {filename}")
                mogp_start_pos = f.tell()
                
                if chunk_size < 64: # MOGP_Header size
                    print(f"  Error: MOGP chunk size {chunk_size} is less than header size 64. Aborting for {filename}.")
                    f.read(chunk_size) 
                    return None
                
                mogp_header = parse_mogp_header(f, filename)
                parsed_group_data['MOGP_Header'] = mogp_header
                
                bytes_read_in_mogp_subchunks = 0
                expected_mogp_subchunk_data_size = chunk_size - 64 # 64 is sizeof(MOGP_Header)
                
                sub_chunks = {}
                while bytes_read_in_mogp_subchunks < expected_mogp_subchunk_data_size:
                    sub_chunk_start_pos = f.tell()
                    sub_id, sub_size = read_chunk_header(f)
                    
                    if sub_id is None:
                        if bytes_read_in_mogp_subchunks < expected_mogp_subchunk_data_size:
                            # print(f"    Warning: Unexpected EOF or read error in MOGP sub-chunks in {filename} after reading {bytes_read_in_mogp_subchunks} of {expected_mogp_subchunk_data_size} sub-chunk data bytes.")
                            pass # Suppress for cleaner output now
                        break 
                    
                    if (sub_chunk_start_pos - (mogp_start_pos + 64)) + 8 + sub_size > expected_mogp_subchunk_data_size:
                        # print(f"    Error: MOGP sub-chunk {sub_id} (size {sub_size}) would exceed MOGP data boundary. Skipping remaining MOGP data.")
                        remaining_mogp_bytes = expected_mogp_subchunk_data_size - (sub_chunk_start_pos - (mogp_start_pos + 64))
                        if remaining_mogp_bytes > 0:
                            f.seek(remaining_mogp_bytes, os.SEEK_CUR)
                        bytes_read_in_mogp_subchunks = expected_mogp_subchunk_data_size
                        break

                    # print(f"    Found MOGP Sub-Chunk: {sub_id}, Size: {sub_size}")
                    current_subchunk_data_pos = f.tell()
                    parser_func = {
                        "MOPY": parse_mopy, "MOVI": parse_movi, "MOVT": parse_movt,
                        "MONR": parse_monr, "MOTV": parse_motv, "MOBA": parse_moba,
                        "MOCV": parse_mocv, "MLIQ": parse_mliq, "MOBN": parse_mobn,
                        "MOBR": parse_mobr, "MODR": parse_modr
                    }.get(sub_id)

                    if parser_func:
                        sub_chunks[sub_id] = parser_func(f, sub_size)
                    else:
                        # print(f"      Skipping unknown or unhandled MOGP sub-chunk: {sub_id}")
                        f.seek(sub_size, os.SEEK_CUR)
                    
                    if f.tell() != current_subchunk_data_pos + sub_size:
                        # print(f"      Warning: Sub-chunk {sub_id} parser did not read full sub-chunk. Read {f.tell() - current_subchunk_data_pos} of {sub_size}. Seeking to end.")
                        f.seek(current_subchunk_data_pos + sub_size, os.SEEK_SET)
                        
                    bytes_read_in_mogp_subchunks = f.tell() - (mogp_start_pos + 64)

                parsed_group_data['MOGP_SubChunks'] = sub_chunks
                
                expected_mogp_end_pos = mogp_start_pos + chunk_size
                if f.tell() != expected_mogp_end_pos:
                    # print(f"  Warning: Did not read entire MOGP chunk for {filename}. Seeking to end.")
                    f.seek(expected_mogp_end_pos, os.SEEK_SET)
            else:
                print(f"  Error: Expected MOGP chunk after MVER, got {chunk_id}. Aborting for {filename}.")
                return None
                
            next_chunk_id, next_chunk_size = read_chunk_header(f)
            if next_chunk_id:
                # print(f"  Warning: Found unexpected chunk {next_chunk_id} after MOGP in {filename}. Skipping.")
                f.seek(next_chunk_size, os.SEEK_CUR)

    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    except EOFError:
        print(f"Error: Unexpected end of file while parsing {filename}.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while parsing {filename}: {e}")
        import traceback
        traceback.print_exc()
        return None

    # print(f"Finished parsing WMO Group File: {filename}")
    return parsed_group_data


def get_visual_geometry(movt_data_list, movi_data_list):
    if not movt_data_list or not movi_data_list:
        # print("DEBUG: get_visual_geometry - movt_data_list or movi_data_list is empty/None")
        return None, None
    
    # movt_data_list is a list of dicts like [{'pos': (x,y,z)}, ...]
    # movi_data_list is a list of indices [idx0, idx1, idx2, ...]
    
    # Анализ уникальности координат в movt_data_list
    # all_vertex_positions = [tuple(v['pos']) for v in movt_data_list]
    # unique_vertex_positions = set(all_vertex_positions)
    # print(f"      INFO in get_visual_geometry: Total vertex entries in MOVT: {len(all_vertex_positions)}, Unique vertex positions: {len(unique_vertex_positions)}")
    # if len(all_vertex_positions) != len(unique_vertex_positions):
    #     print(f"      WARNING in get_visual_geometry: MOVT contains {len(all_vertex_positions) - len(unique_vertex_positions)} duplicate vertex positions.")

    vertices_np = np.array([v['pos'] for v in movt_data_list], dtype=np.float32)
    # print(f"DEBUG: get_visual_geometry - vertices_np shape: {vertices_np.shape}")
    
    faces_list = []
    num_indices = len(movi_data_list)
    num_triangles = num_indices // 3
        
    num_skipped_triangles = 0
    for i in range(num_triangles):
        idx0 = movi_data_list[i*3 + 0]
        idx1 = movi_data_list[i*3 + 1]
        idx2 = movi_data_list[i*3 + 2]

        num_available_vertices = len(vertices_np)
        if idx0 >= num_available_vertices or \
           idx1 >= num_available_vertices or \
           idx2 >= num_available_vertices:
            num_skipped_triangles +=1
            continue 
        faces_list.extend([3, idx0, idx1, idx2])
    
    # if num_skipped_triangles > 0:
    #    print(f"      INFO in get_visual_geometry: Skipped {num_skipped_triangles} triangles due to out-of-bounds vertex indices.")

    if not faces_list:
        # print("DEBUG: get_visual_geometry - No valid faces were extracted.")
        return vertices_np, None # Return vertices even if no faces, to see points
    
    # print(f"DEBUG: get_visual_geometry - faces_list length: {len(faces_list)}")
    return vertices_np, np.array(faces_list, dtype=np.int32)


# get_collision_geometry can remain largely the same for now, as it also relies on MOVT/MOVI
# but selects triangles based on MOBN/MOBR. The same out-of-bounds check for MOVI indices
# within get_visual_geometry (if MOBR points to a MOVI triangle that itself is bad) would apply.
# However, MOBR points to *triangle indices* from MOVI, so the check needs to be on final vertex indices.

def get_collision_geometry(movt_data_list, movi_data_list, mobn_data, mobr_data):
    if not movt_data_list or not movi_data_list or not mobn_data or not mobr_data:
        # print("Collision geometry data incomplete (MOVT, MOVI, MOBN, or MOBR missing).")
        return None, None

    vertices_np = np.array([v['pos'] for v in movt_data_list], dtype=np.float32)
    num_available_vertices = len(vertices_np)
    
    collision_faces_list = []
    num_skipped_triangles_mobr = 0
    
    for node in mobn_data:
        if node['flags'] & 0x4: # Leaf node
            num_node_faces = node['nFaces']
            face_start_index_in_mobr = node['faceStart']
            
            for i in range(num_node_faces):
                if face_start_index_in_mobr + i < len(mobr_data):
                    mobr_triangle_index = mobr_data[face_start_index_in_mobr + i]
                    
                    base_vertex_idx_in_movi = mobr_triangle_index * 3
                    if base_vertex_idx_in_movi + 2 < len(movi_data_list):
                        v_idx0 = movi_data_list[base_vertex_idx_in_movi + 0]
                        v_idx1 = movi_data_list[base_vertex_idx_in_movi + 1]
                        v_idx2 = movi_data_list[base_vertex_idx_in_movi + 2]

                        # Check if these final vertex indices are valid for the MOVT data
                        if v_idx0 >= num_available_vertices or \
                           v_idx1 >= num_available_vertices or \
                           v_idx2 >= num_available_vertices:
                            num_skipped_triangles_mobr +=1
                            continue # Skip this problematic triangle from MOBR list

                        collision_faces_list.extend([3, v_idx0, v_idx1, v_idx2])
                    else:
                        # print(f"Warning: MOBR triangle index {mobr_triangle_index} (from MOBN) points to MOVI data out of bounds.")
                        num_skipped_triangles_mobr +=1 # Count as skipped if can't get indices
                else:
                    # print(f"Warning: MOBN faceStart index {face_start_index_in_mobr + i} out of MOBR bounds.")
                    num_skipped_triangles_mobr +=1 # Count as skipped
                    
    # if num_skipped_triangles_mobr > 0:
    #    print(f"      INFO in get_collision_geometry: Skipped {num_skipped_triangles_mobr} collision triangles due to various out-of-bounds issues.")

    if not collision_faces_list:
        # print("No collision faces were extracted.")
        return vertices_np, None 
        
    return vertices_np, np.array(collision_faces_list, dtype=np.int32)


def visualize_aggregated_wmo_points(script_dir):
    print("\\n--- AGGREGATING ALL WMO GROUP FILES (TEST FUNCTION) ---")
    wmo_group_files_patterns = [
        "Ulduar_Raid_*.wmo"
    ]
    
    all_found_group_files = []
    for pattern in wmo_group_files_patterns:
        all_found_group_files.extend(glob.glob(os.path.join(script_dir, pattern)))
    
    all_found_group_files = sorted(list(set(all_found_group_files)))

    if not all_found_group_files:
        print(f"Error: Could not find any WMO group files matching patterns in {script_dir}")
        return

    print(f"Found {len(all_found_group_files)} WMO group files to process for aggregation:")
    for fname in all_found_group_files:
        print(f"  - {os.path.basename(fname)}")

    all_vertices_aggregated_list = []
    all_faces_aggregated_flat_list = []
    current_vertex_offset = 0

    for wmo_group_file_path in all_found_group_files:
        print(f"\\n--- Aggregating: {os.path.basename(wmo_group_file_path)} ---")
        parsed_data = parse_wmo_group(wmo_group_file_path)

        if parsed_data and 'MOGP_SubChunks' in parsed_data:
            sub_chunks = parsed_data['MOGP_SubChunks']
            movt_chunk_data = sub_chunks.get('MOVT')
            movi_chunk_data = sub_chunks.get('MOVI')

            if movt_chunk_data and movi_chunk_data:
                # Используем get_visual_geometry для получения вершин и граней этой группы
                group_vertices_np, group_faces_flat_np = get_visual_geometry(movt_chunk_data, movi_chunk_data)
                
                if group_vertices_np is not None and group_vertices_np.size > 0:
                    num_group_vertices = len(group_vertices_np)
                    all_vertices_aggregated_list.extend(group_vertices_np.tolist()) # Конвертируем в список для extend
                    
                    if group_faces_flat_np is not None and group_faces_flat_np.size > 0:
                        # Корректируем индексы граней для этой группы
                        # group_faces_flat_np это [3, i0,i1,i2, 3, i3,i4,i5, ...]
                        corrected_group_faces = []
                        for i in range(0, len(group_faces_flat_np), 4):
                            face_type = group_faces_flat_np[i]
                            if face_type == 3: # Треугольник
                                v_idx0 = group_faces_flat_np[i+1] + current_vertex_offset
                                v_idx1 = group_faces_flat_np[i+2] + current_vertex_offset
                                v_idx2 = group_faces_flat_np[i+3] + current_vertex_offset
                                corrected_group_faces.extend([3, v_idx0, v_idx1, v_idx2])
                        all_faces_aggregated_flat_list.extend(corrected_group_faces)
                        print(f"    Added {num_group_vertices} vertices and {len(corrected_group_faces)//4} faces from this group.")
                    else:
                        print(f"    Added {num_group_vertices} vertices from this group (no valid faces).")
                    current_vertex_offset += num_group_vertices
                else:
                    print("    No visual vertices found or extracted from this group.")
            else:
                print("    MOVT or MOVI chunk missing in this group for aggregation.")
        else:
            print("    Failed to parse WMO group file or no MOGP_SubChunks found for aggregation.")

    if not all_vertices_aggregated_list:
        print("\\nNo geometry was aggregated from any WMO group files. Cannot visualize.")
        return

    aggregated_vertices_np = np.array(all_vertices_aggregated_list, dtype=np.float32)
    aggregated_mesh_polydata = pv.PolyData(aggregated_vertices_np)

    if all_faces_aggregated_flat_list: # Если есть хоть какие-то грани
        aggregated_faces_flat_np = np.array(all_faces_aggregated_flat_list, dtype=np.int32)
        # Попытаемся создать меш с гранями, но будем готовы к ошибкам
        try:
            temp_mesh_with_faces = pv.PolyData(aggregated_vertices_np, faces=aggregated_faces_flat_np)
            if temp_mesh_with_faces.n_points > 0 and temp_mesh_with_faces.n_cells > 0:
                aggregated_mesh_polydata = temp_mesh_with_faces # Используем меш с гранями, если он валиден
                print(f"  Aggregated mesh has {temp_mesh_with_faces.n_cells} cells.")
            else:
                print("  Aggregated mesh with faces was invalid, will display points only.")
        except Exception as e_agg_face_poly:
            print(f"  Error creating aggregated PolyData with faces: {e_agg_face_poly}. Will display points only.")

    print(f"\\n--- Aggregated Geometry Summary ---")
    print(f"  Total aggregated vertices: {len(aggregated_vertices_np)}")
    if aggregated_mesh_polydata.n_cells > 0:
        print(f"  Total aggregated faces (triangles): {aggregated_mesh_polydata.n_cells}")
    else:
        print("  Aggregated geometry will be displayed as points (no valid faces or faces not used).")

    if np.isnan(aggregated_vertices_np).any() or np.isinf(aggregated_vertices_np).any():
        print("  WARNING: NaN or Inf values found in aggregated_vertices! Visualization might fail or be incorrect.")

    print("\\n--- Attempting PyVista Visualization for AGGREGATED WMO Geometry ---")
    try:
        plotter_agg = pv.Plotter(window_size=[1600, 900])
        
        points_to_display_normalized = aggregated_mesh_polydata.points.copy()
        if points_to_display_normalized.size > 0:
            min_coords = np.min(points_to_display_normalized, axis=0)
            max_coords = np.max(points_to_display_normalized, axis=0)
            range_coords = max_coords - min_coords
            range_coords[range_coords == 0] = 1 
            points_to_display_normalized = (points_to_display_normalized - min_coords) / range_coords
            points_to_display_normalized = points_to_display_normalized * 2 - 1
        
        normalized_display_mesh = pv.PolyData(points_to_display_normalized)
        if aggregated_mesh_polydata.n_cells > 0 and aggregated_mesh_polydata.faces is not None:
            # Если исходный агрегированный меш имел грани, пытаемся их сохранить с нормализованными точками
            try:
                normalized_display_mesh = pv.PolyData(points_to_display_normalized, faces=aggregated_mesh_polydata.faces)
                print("  Displaying aggregated mesh WITH FACES (normalized).")
                plotter_agg.add_mesh(normalized_display_mesh, 
                                     style='surface', 
                                     color='lightcoral', 
                                     show_edges=True, 
                                     edge_color='darkgrey', 
                                     line_width=0.1, # Тонкие грани
                                     label="Aggregated WMO Surface (Normalized)")
            except Exception as e_norm_face_poly:
                print(f"  Error creating normalized PolyData with faces: {e_norm_face_poly}. Displaying points only.")
                normalized_display_mesh = pv.PolyData(points_to_display_normalized) # Откат к точкам
                plotter_agg.add_mesh(normalized_display_mesh, 
                                 color='orange', 
                                 point_size=2, 
                                 render_points_as_spheres=True,
                                 label="Aggregated WMO Points (Normalized - Fallback)")
        else:
            print("  Displaying aggregated mesh as POINTS (normalized).")
            plotter_agg.add_mesh(normalized_display_mesh, 
                                 color='deepskyblue', 
                                 point_size=1.5, # Чуть меньше для большого количества
                                 render_points_as_spheres=True,
                                 label="Aggregated WMO Points (Normalized)")

        plotter_agg.add_legend()
        plotter_agg.add_text("AGGREGATED WMO Groups (Normalized - TEST)", position='upper_edge', font_size=10)
        plotter_agg.camera_position = 'iso'
        plotter_agg.enable_image_style() # Возвращаем enable_image_style()
        # plotter_agg.enable_zoom_style()  # Комментируем enable_zoom_style()
        plotter_agg.add_axes()
        
        print(f"\\nShowing PyVista plot for AGGREGATED WMO data... Close the plot window to allow script to finish.")
        plotter_agg.show(interactive=True, auto_close=False)

    except Exception as e_agg_viz:
        print(f"ERROR in the aggregated visualization block: {e_agg_viz}")
        import traceback
        traceback.print_exc()


def visualize_aggregated_collision_geometry(script_dir):
    print("\\n--- AGGREGATING COLLISION GEOMETRY FROM ALL WMO GROUP FILES (TEST FUNCTION) ---")
    # Используем те же паттерны файлов, что и для визуальной геометрии
    wmo_group_files_patterns = [
        "Ulduar_Raid_*.wmo" # Пример, измените на нужные вам
        # "Blacktemple_*.wmo", 
        # "BlackTemple_*.wmo", 
        # "blacktemple_*.wmo",
        # "Kharazan_instance_*.wmo"
    ]
    
    all_found_group_files = []
    for pattern in wmo_group_files_patterns:
        all_found_group_files.extend(glob.glob(os.path.join(script_dir, pattern)))
    
    all_found_group_files = sorted(list(set(all_found_group_files)))

    if not all_found_group_files:
        print(f"Error: Could not find any WMO group files matching patterns in {script_dir} for collision geometry.")
        return

    print(f"Found {len(all_found_group_files)} WMO group files to process for collision geometry aggregation:")
    for fname in all_found_group_files:
        print(f"  - {os.path.basename(fname)}")

    all_collision_vertices_list = []
    all_collision_faces_flat_list = []
    current_vertex_offset = 0

    for wmo_group_file_path in all_found_group_files:
        print(f"\\n--- Aggregating Collision Geo: {os.path.basename(wmo_group_file_path)} ---")
        parsed_data = parse_wmo_group(wmo_group_file_path)

        if parsed_data and 'MOGP_SubChunks' in parsed_data:
            sub_chunks = parsed_data['MOGP_SubChunks']
            movt_chunk_data = sub_chunks.get('MOVT')
            movi_chunk_data = sub_chunks.get('MOVI')
            mobn_chunk_data = sub_chunks.get('MOBN')
            mobr_chunk_data = sub_chunks.get('MOBR')

            if movt_chunk_data and movi_chunk_data and mobn_chunk_data and mobr_chunk_data:
                group_coll_vertices_np, group_coll_faces_flat_np = get_collision_geometry(
                    movt_chunk_data, movi_chunk_data, mobn_chunk_data, mobr_chunk_data
                )
                
                if group_coll_vertices_np is not None and group_coll_vertices_np.size > 0:
                    num_group_vertices = len(group_coll_vertices_np)
                    all_collision_vertices_list.extend(group_coll_vertices_np.tolist())
                    
                    if group_coll_faces_flat_np is not None and group_coll_faces_flat_np.size > 0:
                        corrected_group_faces = []
                        for i in range(0, len(group_coll_faces_flat_np), 4):
                            face_type = group_coll_faces_flat_np[i]
                            if face_type == 3:
                                v_idx0 = group_coll_faces_flat_np[i+1] + current_vertex_offset
                                v_idx1 = group_coll_faces_flat_np[i+2] + current_vertex_offset
                                v_idx2 = group_coll_faces_flat_np[i+3] + current_vertex_offset
                                corrected_group_faces.extend([3, v_idx0, v_idx1, v_idx2])
                        all_collision_faces_flat_list.extend(corrected_group_faces)
                        print(f"    Added {num_group_vertices} collision vertices and {len(corrected_group_faces)//4} collision faces.")
                    else:
                        print(f"    Added {num_group_vertices} collision vertices (no valid collision faces).")
                    current_vertex_offset += num_group_vertices
                else:
                    print("    No collision vertices found or extracted from this group.")
            else:
                print("    MOVT, MOVI, MOBN, or MOBR chunk missing. Cannot extract collision geometry.")
        else:
            print("    Failed to parse WMO group file or no MOGP_SubChunks found for collision aggregation.")

    if not all_collision_vertices_list:
        print("\\nNo collision geometry was aggregated. Cannot visualize.")
        return

    aggregated_coll_vertices_np = np.array(all_collision_vertices_list, dtype=np.float32)
    aggregated_coll_mesh_polydata = pv.PolyData(aggregated_coll_vertices_np)

    if all_collision_faces_flat_list:
        aggregated_coll_faces_flat_np = np.array(all_collision_faces_flat_list, dtype=np.int32)
        try:
            temp_mesh_with_faces = pv.PolyData(aggregated_coll_vertices_np, faces=aggregated_coll_faces_flat_np)
            if temp_mesh_with_faces.n_points > 0 and temp_mesh_with_faces.n_cells > 0:
                aggregated_coll_mesh_polydata = temp_mesh_with_faces
                print(f"  Aggregated collision mesh has {temp_mesh_with_faces.n_cells} cells.")
            else:
                print("  Aggregated collision mesh with faces was invalid, will display points only.")
        except Exception as e_agg_coll_face_poly:
            print(f"  Error creating aggregated collision PolyData with faces: {e_agg_coll_face_poly}. Will display points only.")

    print(f"\\n--- Aggregated Collision Geometry Summary ---")
    print(f"  Total aggregated collision vertices: {len(aggregated_coll_vertices_np)}")
    if aggregated_coll_mesh_polydata.n_cells > 0:
        print(f"  Total aggregated collision faces: {aggregated_coll_mesh_polydata.n_cells}")
    else:
        print("  Aggregated collision geometry will be displayed as points.")

    if np.isnan(aggregated_coll_vertices_np).any() or np.isinf(aggregated_coll_vertices_np).any():
        print("  WARNING: NaN or Inf values found in aggregated collision_vertices! Visualization might be incorrect.")

    print("\\n--- Attempting PyVista Visualization for AGGREGATED COLLISION Geometry ---")
    try:
        plotter_coll_agg = pv.Plotter(window_size=[1600, 900])
        
        points_to_display_normalized = aggregated_coll_mesh_polydata.points.copy()
        if points_to_display_normalized.size > 0:
            min_coords = np.min(points_to_display_normalized, axis=0)
            max_coords = np.max(points_to_display_normalized, axis=0)
            range_coords = max_coords - min_coords
            range_coords[range_coords == 0] = 1 
            points_to_display_normalized = (points_to_display_normalized - min_coords) / range_coords
            points_to_display_normalized = points_to_display_normalized * 2 - 1
        
        normalized_coll_display_mesh = pv.PolyData(points_to_display_normalized)
        if aggregated_coll_mesh_polydata.n_cells > 0 and aggregated_coll_mesh_polydata.faces is not None:
            try:
                normalized_coll_display_mesh = pv.PolyData(points_to_display_normalized, faces=aggregated_coll_mesh_polydata.faces)
                print("  Displaying aggregated COLLISION mesh WITH FACES (normalized).")
                plotter_coll_agg.add_mesh(normalized_coll_display_mesh, 
                                     style='surface', 
                                     color='mediumseagreen', 
                                     show_edges=True, 
                                     edge_color='darkgreen', 
                                     line_width=0.1,
                                     label="Aggregated Collision Surface (Normalized)")
            except Exception as e_norm_coll_face_poly:
                print(f"  Error creating normalized collision PolyData with faces: {e_norm_coll_face_poly}. Displaying points only.")
                normalized_coll_display_mesh = pv.PolyData(points_to_display_normalized)
                plotter_coll_agg.add_mesh(normalized_coll_display_mesh, 
                                 color='greenyellow', 
                                 point_size=2, 
                                 render_points_as_spheres=True,
                                 label="Aggregated Collision Points (Normalized - Fallback)")
        else:
            print("  Displaying aggregated COLLISION mesh as POINTS (normalized).")
            plotter_coll_agg.add_mesh(normalized_coll_display_mesh, 
                                 color='lime', 
                                 point_size=1.5,
                                 render_points_as_spheres=True,
                                 label="Aggregated Collision Points (Normalized)")

        plotter_coll_agg.add_legend()
        plotter_coll_agg.add_text("AGGREGATED WMO Collision Geo (Normalized - TEST)", position='upper_edge', font_size=10)
        plotter_coll_agg.camera_position = 'iso'
        plotter_coll_agg.enable_image_style()
        plotter_coll_agg.add_axes()
        
        print(f"\\nShowing PyVista plot for AGGREGATED COLLISION data... Close window to finish.")
        plotter_coll_agg.show(interactive=True, auto_close=False)

    except Exception as e_agg_coll_viz:
        print(f"ERROR in the aggregated collision visualization block: {e_agg_coll_viz}")
        import traceback
        traceback.print_exc()


def visualize_visual_vs_collision_single_group(script_dir, target_wmo_group_file):
    print(f"\\n--- VISUALIZING VISUAL VS COLLISION FOR SINGLE GROUP: {target_wmo_group_file} ---")
    wmo_group_file_path = os.path.join(script_dir, target_wmo_group_file)

    if not os.path.exists(wmo_group_file_path):
        print(f"Error: Could not find the target WMO group file: {wmo_group_file_path}")
        return

    print(f"--- Processing single file: {os.path.basename(wmo_group_file_path)} ---")
    parsed_data = parse_wmo_group(wmo_group_file_path)

    if not parsed_data or 'MOGP_SubChunks' not in parsed_data:
        print("  Failed to parse WMO group file or no MOGP_SubChunks found.")
        return

    sub_chunks = parsed_data['MOGP_SubChunks']
    movt_data = sub_chunks.get('MOVT')
    movi_data = sub_chunks.get('MOVI')
    mobn_data = sub_chunks.get('MOBN')
    mobr_data = sub_chunks.get('MOBR')

    if not movt_data or not movi_data:
        print("  MOVT or MOVI chunk missing. Cannot extract base geometry.")
        return

    # 1. Получаем визуальную геометрию
    print("  Extracting visual geometry...")
    visual_vertices_np, visual_faces_flat_np = get_visual_geometry(movt_data, movi_data)
    visual_mesh = None
    if visual_vertices_np is not None and visual_faces_flat_np is not None and visual_faces_flat_np.size > 0:
        try:
            visual_mesh = pv.PolyData(visual_vertices_np, faces=visual_faces_flat_np)
            print(f"    Visual mesh: {visual_mesh.n_points} points, {visual_mesh.n_cells} cells")
        except Exception as e:
            print(f"    Error creating visual PolyData: {e}")
    elif visual_vertices_np is not None:
        visual_mesh = pv.PolyData(visual_vertices_np) # Только точки
        print(f"    Visual mesh: {visual_mesh.n_points} points, 0 cells (points only)")
    else:
        print("    No visual vertices found.")

    # 2. Получаем коллизионную геометрию (если есть MOBN/MOBR)
    collision_mesh = None
    if mobn_data and mobr_data: # MOBN/MOBR могут отсутствовать
        print("  Extracting collision geometry...")
        collision_vertices_np, collision_faces_flat_np = get_collision_geometry(movt_data, movi_data, mobn_data, mobr_data)
        if collision_vertices_np is not None and collision_faces_flat_np is not None and collision_faces_flat_np.size > 0:
            try:
                collision_mesh = pv.PolyData(collision_vertices_np, faces=collision_faces_flat_np)
                print(f"    Collision mesh: {collision_mesh.n_points} points, {collision_mesh.n_cells} cells")
            except Exception as e:
                print(f"    Error creating collision PolyData: {e}")
        elif collision_vertices_np is not None:
            collision_mesh = pv.PolyData(collision_vertices_np) # Только точки
            print(f"    Collision mesh: {collision_mesh.n_points} points, 0 cells (points only)")
        else:
            print("    No collision vertices found (though MOBN/MOBR exist).")
    else:
        print("  MOBN or MOBR chunk missing. Skipping collision geometry.")

    if not visual_mesh and not collision_mesh:
        print("  No geometry to display.")
        return

    # 3. Визуализация
    plotter = pv.Plotter(window_size=[1200, 900])
    plotter.add_text(f"Comparison for {target_wmo_group_file}", position='upper_edge', font_size=10)

    if visual_mesh and visual_mesh.n_points > 0:
        # Нормализуем вершины визуального меша (они же и для коллизионного, т.к. источник один - MOVT)
        points_normalized = visual_mesh.points.copy()
        min_coords = np.min(points_normalized, axis=0)
        max_coords = np.max(points_normalized, axis=0)
        range_coords = max_coords - min_coords
        range_coords[range_coords == 0] = 1 
        points_normalized = (points_normalized - min_coords) / range_coords
        points_normalized = points_normalized * 2 - 1
        
        normalized_visual_mesh_display = pv.PolyData(points_normalized, faces=visual_mesh.faces if visual_mesh.n_cells > 0 else None)

        if normalized_visual_mesh_display.n_cells > 0:
            plotter.add_mesh(normalized_visual_mesh_display, 
                             color='green', 
                             style='surface', 
                             opacity=1.0, 
                             show_edges=True, 
                             edge_color='darkgreen', 
                             line_width=0.1,
                             label="Visual Geometry")
            print("    Added Visual Geometry (surface) to plotter.")
        elif normalized_visual_mesh_display.n_points > 0:
             plotter.add_mesh(normalized_visual_mesh_display, 
                             color='green', 
                             point_size=3, 
                             render_points_as_spheres=False,
                             opacity=0.5,
                             label="Visual Points")
             print("    Added Visual Geometry (points) to plotter.")

    if collision_mesh and collision_mesh.n_points > 0:
        # Используем те же нормализованные точки, т.к. вершины из MOVT
        # но грани свои (подмножество от MOVI)
        normalized_collision_mesh_display = pv.PolyData(points_normalized, faces=collision_mesh.faces if collision_mesh.n_cells > 0 else None)
        
        if normalized_collision_mesh_display.n_cells > 0:
            plotter.add_mesh(normalized_collision_mesh_display, 
                             color='red', 
                             style='surface', # Изменено на surface
                             opacity=1.0, # Непрозрачный
                             show_edges=True, 
                             edge_color='darkred', 
                             line_width=0.1, # Можно сделать таким же, как у визуального
                             label="Collision Geometry")
            print("    Added Collision Geometry (surface) to plotter.")
        elif normalized_collision_mesh_display.n_points > 0: # Если только точки коллизии
             plotter.add_mesh(normalized_collision_mesh_display, 
                             color='red', 
                             point_size=5, 
                             render_points_as_spheres=True, 
                             label="Collision Points")
             print("    Added Collision Geometry (points) to plotter.")

    plotter.add_legend()
    plotter.enable_image_style()
    plotter.add_axes()
    print(f"\\nShowing PyVista plot for single group comparison... Close window to finish.")
    plotter.show(interactive=True, auto_close=False)


def visualize_aggregated_visual_vs_collision(script_dir, wmo_group_files_patterns):
    print(f"\\n--- AGGREGATING VISUAL VS COLLISION FOR PATTERNS: {wmo_group_files_patterns} ---")
    
    all_found_group_files = []
    for pattern in wmo_group_files_patterns:
        all_found_group_files.extend(glob.glob(os.path.join(script_dir, pattern)))
    all_found_group_files = sorted(list(set(all_found_group_files)))

    if not all_found_group_files:
        print(f"Error: Could not find any WMO group files matching patterns in {script_dir}")
        return

    print(f"Found {len(all_found_group_files)} WMO group files to process for aggregated comparison:")
    for fname in all_found_group_files:
        print(f"  - {os.path.basename(fname)}")

    # Для визуальной геометрии
    all_visual_vertices_list = []
    all_visual_faces_flat_list = []
    current_visual_vertex_offset = 0

    # Для коллизионной геометрии
    # Вершины будут браться из all_visual_vertices_list, так как MOVT общий.
    # Нам нужно будет отдельно собирать грани коллизий и корректно смещать их индексы 
    # относительно ОБЩЕГО пула вершин (all_visual_vertices_list).
    all_collision_faces_flat_list = []
    # current_collision_vertex_offset не нужен отдельно, если мы правильно мапим на визуальные вершины.

    temp_group_vertex_counts = [] # Чтобы знать смещения для коллизионных граней каждой группы

    for wmo_group_file_path in all_found_group_files:
        print(f"\\n--- Processing for Aggregated Comparison: {os.path.basename(wmo_group_file_path)} ---")
        parsed_data = parse_wmo_group(wmo_group_file_path)

        if not parsed_data or 'MOGP_SubChunks' not in parsed_data:
            print("    Failed to parse WMO group file or no MOGP_SubChunks found.")
            temp_group_vertex_counts.append(0) # Добавляем 0, чтобы сохранить соответствие индексов
            continue

        sub_chunks = parsed_data['MOGP_SubChunks']
        movt_data = sub_chunks.get('MOVT')
        movi_data = sub_chunks.get('MOVI')
        mobn_data = sub_chunks.get('MOBN')
        mobr_data = sub_chunks.get('MOBR')

        if not movt_data or not movi_data:
            print("    MOVT or MOVI chunk missing. Cannot extract base geometry for this group.")
            temp_group_vertex_counts.append(0)
            continue
        
        # 1. Обработка визуальной геометрии для этой группы
        group_visual_vertices_np, group_visual_faces_flat_np = get_visual_geometry(movt_data, movi_data)
        num_group_visual_vertices = 0
        if group_visual_vertices_np is not None and group_visual_vertices_np.size > 0:
            num_group_visual_vertices = len(group_visual_vertices_np)
            all_visual_vertices_list.extend(group_visual_vertices_np.tolist())
            
            if group_visual_faces_flat_np is not None and group_visual_faces_flat_np.size > 0:
                corrected_group_visual_faces = []
                for i in range(0, len(group_visual_faces_flat_np), 4):
                    if group_visual_faces_flat_np[i] == 3:
                        v_idx0 = group_visual_faces_flat_np[i+1] + current_visual_vertex_offset
                        v_idx1 = group_visual_faces_flat_np[i+2] + current_visual_vertex_offset
                        v_idx2 = group_visual_faces_flat_np[i+3] + current_visual_vertex_offset
                        corrected_group_visual_faces.extend([3, v_idx0, v_idx1, v_idx2])
                all_visual_faces_flat_list.extend(corrected_group_visual_faces)
                print(f"    Visual: Added {num_group_visual_vertices} vertices, {len(corrected_group_visual_faces)//4} faces.")
            else:
                print(f"    Visual: Added {num_group_visual_vertices} vertices (no faces).")
        else:
            print("    Visual: No vertices found.")
        
        temp_group_vertex_counts.append(num_group_visual_vertices)

        # 2. Обработка коллизионной геометрии для этой группы (если есть MOBN/MOBR)
        if mobn_data and mobr_data:
            group_coll_vertices_np, group_coll_faces_flat_np = get_collision_geometry(movt_data, movi_data, mobn_data, mobr_data)
            # group_coll_vertices_np здесь фактически те же, что и group_visual_vertices_np, но могут быть отфильтрованы.
            # Нам важны group_coll_faces_flat_np, так как они уже отфильтрованы по MOBN/MOBR 
            # и их индексы УЖЕ относятся к оригинальному MOVT данной группы.

            if group_coll_faces_flat_np is not None and group_coll_faces_flat_np.size > 0:
                corrected_group_collision_faces = []
                for i in range(0, len(group_coll_faces_flat_np), 4):
                    if group_coll_faces_flat_np[i] == 3:
                        # Индексы в group_coll_faces_flat_np УЖЕ для вершин из movt_data этой группы.
                        # Нам нужно их сместить на current_visual_vertex_offset, чтобы они указывали
                        # на правильные вершины в общем агрегированном списке all_visual_vertices_list.
                        v_idx0 = group_coll_faces_flat_np[i+1] + current_visual_vertex_offset
                        v_idx1 = group_coll_faces_flat_np[i+2] + current_visual_vertex_offset
                        v_idx2 = group_coll_faces_flat_np[i+3] + current_visual_vertex_offset
                        corrected_group_collision_faces.extend([3, v_idx0, v_idx1, v_idx2])
                all_collision_faces_flat_list.extend(corrected_group_collision_faces)
                print(f"    Collision: Added {len(corrected_group_collision_faces)//4} faces (using existing vertices).")
            else:
                print("    Collision: No faces found for this group.")
        else:
            print("    Collision: MOBN/MOBR missing for this group.")

        current_visual_vertex_offset += num_group_visual_vertices

    # --- Создание и визуализация агрегированных мешей ---
    if not all_visual_vertices_list:
        print("\\nNo visual geometry was aggregated. Cannot visualize comparison.")
        return

    aggregated_visual_vertices_np = np.array(all_visual_vertices_list, dtype=np.float32)

    # Нормализация (только один раз для всех вершин)
    points_normalized = aggregated_visual_vertices_np.copy()
    if points_normalized.size > 0:
        min_coords = np.min(points_normalized, axis=0)
        max_coords = np.max(points_normalized, axis=0)
        range_coords = max_coords - min_coords
        range_coords[range_coords == 0] = 1
        points_normalized = (points_normalized - min_coords) / range_coords * 2 - 1
    else:
        print("Нет точек для нормализации.")
        return

    plotter = pv.Plotter(window_size=[1600, 1000])
    plotter.add_text(f"Aggregated Comparison for {wmo_group_files_patterns}", position='upper_edge', font_size=10)

    # Агрегированный визуальный меш
    if all_visual_faces_flat_list:
        aggregated_visual_faces_np = np.array(all_visual_faces_flat_list, dtype=np.int32)
        try:
            normalized_visual_display_mesh = pv.PolyData(points_normalized, faces=aggregated_visual_faces_np)
            if normalized_visual_display_mesh.n_points > 0 and normalized_visual_display_mesh.n_cells > 0:
                plotter.add_mesh(normalized_visual_display_mesh, 
                                 color='green', 
                                 style='surface', 
                                 opacity=1.0, 
                                 show_edges=True, 
                                 edge_color='darkgreen', 
                                 line_width=0.1,
                                 label=f"Чисто Визуальные ({normalized_visual_display_mesh.n_cells} три)")
                print(f"  Отрисован Чисто Визуальный меш: {normalized_visual_display_mesh.n_cells} треугольников.")
        except Exception as e: print(f"  Ошибка создания Чисто Визуального меша: {e}")
    else:
        print("  Нет Чисто Визуальных треугольников для отрисовки.")

    # Агрегированный коллизионный меш (будет рисоваться поверх зеленого)
    if all_collision_faces_flat_list:
        aggregated_collision_faces_np = np.array(all_collision_faces_flat_list, dtype=np.int32)
        try:
            # Используем те же points_normalized, так как вершины общие
            normalized_collision_display_mesh = pv.PolyData(points_normalized, faces=aggregated_collision_faces_np)
            if normalized_collision_display_mesh.n_points > 0 and normalized_collision_display_mesh.n_cells > 0:
                plotter.add_mesh(normalized_collision_display_mesh, 
                                 color='red', 
                                 style='surface', # Изменено на surface
                                 opacity=1.0, # Непрозрачный
                                 show_edges=True, 
                                 edge_color='darkred', 
                                 line_width=0.1, # Можно сделать таким же, как у визуального
                                 label=f"Коллизионные ({normalized_collision_display_mesh.n_cells} три)")
                print(f"  Отрисован Коллизионный меш: {normalized_collision_display_mesh.n_cells} треугольников.")
        except Exception as e: print(f"  Ошибка создания Коллизионного меша: {e}")
    else:
        print("  Нет коллизионных треугольников для отрисовки.")
    
    if not all_visual_faces_flat_list and not all_collision_faces_flat_list and points_normalized.size > 0:
        print("  Нет граней для отображения, показываю только точки вершин...")
        plotter.add_mesh(pv.PolyData(points_normalized), color='grey', point_size=1, label="Все вершины (нет граней)")

    plotter.add_legend()
    plotter.enable_image_style()
    plotter.add_axes()
    print(f"\\nОкно PyVista для Агрегированного сравнения... Закройте для завершения.")
    plotter.show(interactive=True, auto_close=False)


def धारा_метод_1_визуализировать_агрегированные_разделённые_геометрии(script_dir, wmo_group_files_patterns):
    print(f"\\n--- МЕТОД 1: АГРЕГАЦИЯ И РАЗДЕЛЕНИЕ ВИЗУАЛЬНОЙ И КОЛЛИЗИОННОЙ ГЕОМЕТРИИ ---")
    print(f"Паттерны файлов: {wmo_group_files_patterns}")

    all_found_group_files = []
    for pattern in wmo_group_files_patterns:
        all_found_group_files.extend(glob.glob(os.path.join(script_dir, pattern)))
    all_found_group_files = sorted(list(set(all_found_group_files)))

    if not all_found_group_files:
        print(f"Ошибка: Не найдены WMO файлы групп по паттернам в {script_dir}")
        return

    print(f"Найдено {len(all_found_group_files)} WMO файлов групп для обработки:")
    for fname in all_found_group_files: print(f"  - {os.path.basename(fname)}")

    all_vertices_list = []
    purely_visual_triangles_faces_list = [] 
    collision_triangles_faces_list = []
    
    current_total_vertex_offset = 0
    total_visual_tri_count_from_movi = 0
    total_valid_visual_tri_count = 0
    total_collision_tri_count = 0
    total_purely_visual_tri_count = 0

    for wmo_group_file_path in all_found_group_files:
        filename = os.path.basename(wmo_group_file_path)
        print(f"\\n--- Обработка группы: {filename} ---")
        parsed_data = parse_wmo_group(wmo_group_file_path)

        if not parsed_data or 'MOGP_SubChunks' not in parsed_data:
            print("    Ошибка парсинга или отсутствуют MOGP_SubChunks.")
            continue

        sub_chunks = parsed_data['MOGP_SubChunks']
        movt_data = sub_chunks.get('MOVT')
        movi_data = sub_chunks.get('MOVI')
        mobn_data = sub_chunks.get('MOBN')
        mobr_data = sub_chunks.get('MOBR')

        if not movt_data or not movi_data:
            print("    Отсутствуют MOVT или MOVI. Пропуск группы.")
            continue

        group_vertices_np = np.array([v['pos'] for v in movt_data], dtype=np.float32)
        if group_vertices_np.size == 0:
            print("    MOVT не содержит вершин. Пропуск группы.")
            continue
        
        num_group_vertices = len(group_vertices_np)
        all_vertices_list.extend(group_vertices_np.tolist())

        set_visual_triangles_local_indices = set()
        count_original_movi_triangles = len(movi_data) // 3
        total_visual_tri_count_from_movi += count_original_movi_triangles
        
        for i in range(0, len(movi_data), 3):
            if i + 2 < len(movi_data):
                idx0, idx1, idx2 = movi_data[i], movi_data[i+1], movi_data[i+2]
                if not (idx0 < num_group_vertices and idx1 < num_group_vertices and idx2 < num_group_vertices):
                    continue
                set_visual_triangles_local_indices.add(tuple(sorted((idx0, idx1, idx2))))
        
        num_valid_visual_triangles_in_group = len(set_visual_triangles_local_indices)
        total_valid_visual_tri_count += num_valid_visual_triangles_in_group
        print(f"    Всего треугольников в MOVI: {count_original_movi_triangles}")
        print(f"    Из них уникальных валидных визуальных треугольников в группе: {num_valid_visual_triangles_in_group}")

        set_collision_triangles_local_indices = set()
        if mobn_data and mobr_data:
            for node in mobn_data:
                if node['flags'] & 0x4: 
                    for i_face in range(node['nFaces']):
                        mobr_list_idx = node['faceStart'] + i_face
                        if mobr_list_idx < len(mobr_data):
                            mobr_triangle_idx_in_movi = mobr_data[mobr_list_idx]
                            movi_base_vertex_idx = mobr_triangle_idx_in_movi * 3
                            if movi_base_vertex_idx + 2 < len(movi_data):
                                v_idx0 = movi_data[movi_base_vertex_idx + 0]
                                v_idx1 = movi_data[movi_base_vertex_idx + 1]
                                v_idx2 = movi_data[movi_base_vertex_idx + 2]
                                if not (v_idx0 < num_group_vertices and v_idx1 < num_group_vertices and v_idx2 < num_group_vertices):
                                    continue
                                set_collision_triangles_local_indices.add(tuple(sorted((v_idx0, v_idx1, v_idx2))))
        
        num_collision_triangles_in_group = len(set_collision_triangles_local_indices)
        total_collision_tri_count += num_collision_triangles_in_group
        print(f"    Всего уникальных валидных коллизионных треугольников в группе: {num_collision_triangles_in_group}")

        set_purely_visual_triangles_local = set_visual_triangles_local_indices - set_collision_triangles_local_indices
        num_purely_visual_in_group = len(set_purely_visual_triangles_local)
        total_purely_visual_tri_count += num_purely_visual_in_group
        print(f"    Из них \'чисто визуальных\' (не в коллизии): {num_purely_visual_in_group}") # Исправлено

        for v0, v1, v2 in set_purely_visual_triangles_local:
            purely_visual_triangles_faces_list.extend([3, v0 + current_total_vertex_offset, v1 + current_total_vertex_offset, v2 + current_total_vertex_offset])
        
        for v0, v1, v2 in set_collision_triangles_local_indices:
            collision_triangles_faces_list.extend([3, v0 + current_total_vertex_offset, v1 + current_total_vertex_offset, v2 + current_total_vertex_offset])

        current_total_vertex_offset += num_group_vertices

    print("\\n--- Общая статистика по всем группам (Метод 1) ---")
    print(f"  Всего вершин из MOVT (агрегировано): {len(all_vertices_list)}")
    print(f"  Всего треугольников в MOVI (сумма по группам, до уник./валид.): {total_visual_tri_count_from_movi}")
    print(f"  Всего уникальных валидных визуальных треугольников: {total_valid_visual_tri_count}")
    print(f"  Всего уникальных валидных коллизионных треугольников: {total_collision_tri_count}")
    print(f"  Всего \'чисто визуальных\' треугольников (разница): {total_purely_visual_tri_count}") # Исправлено
    
    if not all_vertices_list:
        print("\\nНет вершин для визуализации.")
        return

    aggregated_vertices_np = np.array(all_vertices_list, dtype=np.float32)
    points_normalized = aggregated_vertices_np.copy()
    if points_normalized.size > 0:
        min_coords, max_coords = np.min(points_normalized, axis=0), np.max(points_normalized, axis=0)
        range_coords = max_coords - min_coords
        range_coords[range_coords == 0] = 1
        points_normalized = (points_normalized - min_coords) / range_coords * 2 - 1
    else:
        print("Нет точек для нормализации.")
        return

    plotter = pv.Plotter(window_size=[1600, 1000])
    plotter.add_text(f"Метод 1: Раздельные меши для {wmo_group_files_patterns}", position='upper_edge', font_size=10)

    if purely_visual_triangles_faces_list:
        purely_visual_faces_np = np.array(purely_visual_triangles_faces_list, dtype=np.int32)
        try:
            purely_visual_mesh = pv.PolyData(points_normalized, faces=purely_visual_faces_np)
            if purely_visual_mesh.n_points > 0 and purely_visual_mesh.n_cells > 0:
                plotter.add_mesh(purely_visual_mesh, color='green', style='surface', opacity=1.0,
                                 show_edges=True, edge_color='darkgreen', line_width=0.1,
                                 label=f"Чисто Визуальные ({purely_visual_mesh.n_cells} три)")
                print(f"  Отрисован \'Чисто Визуальный\' меш: {purely_visual_mesh.n_cells} треугольников.")
        except Exception as e: print(f"  Ошибка создания \'Чисто Визуального\' меша: {e}")
    else:
        print("  Нет \'чисто визуальных\' треугольников для отрисовки.")

    if collision_triangles_faces_list:
        collision_faces_np = np.array(collision_triangles_faces_list, dtype=np.int32)
        try:
            collision_mesh = pv.PolyData(points_normalized, faces=collision_faces_np)
            if collision_mesh.n_points > 0 and collision_mesh.n_cells > 0:
                plotter.add_mesh(collision_mesh, color='red', style='surface', opacity=1.0,
                                 show_edges=True, edge_color='darkred', line_width=0.1,
                                 label=f"Коллизионные ({collision_mesh.n_cells} три)")
                print(f"  Отрисован Коллизионный меш: {collision_mesh.n_cells} треугольников.")
        except Exception as e: print(f"  Ошибка создания Коллизионного меша: {e}")
    else:
        print("  Нет коллизионных треугольников для отрисовки.")
    
    if not purely_visual_triangles_faces_list and not collision_triangles_faces_list and points_normalized.size > 0:
        print("  Нет граней для отображения, показываю только точки вершин...")
        plotter.add_mesh(pv.PolyData(points_normalized), color='grey', point_size=1, label="Все вершины (нет граней)")

    plotter.add_legend()
    plotter.enable_image_style()
    plotter.add_axes()
    print(f"\\nОкно PyVista для Метода 1... Закройте для завершения.")
    plotter.show(interactive=True, auto_close=False)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    VISUALIZE_AGGREGATED_VISUAL = False
    VISUALIZE_AGGREGATED_COLLISION = False
    VISUALIZE_SINGLE_GROUP_COMPARISON = False
    VISUALIZE_AGGREGATED_COMPARISON_ПОДХОД2 = False # Переименован для ясности
    VISUALIZE_AGGREGATED_COMPARISON_ПОДХОД1 = True  # Новый флаг для этого метода

    TARGET_SINGLE_GROUP_FILE = "Ulduar_Raid_000.wmo"
    # AGGREGATED_PATTERNS = ["ND_Dalaran_*.wmo"]
    AGGREGATED_PATTERNS = ["Blacktemple_*.wmo"]
    # AGGREGATED_PATTERNS = ["Blacktemple_000.wmo"] # Для теста одной группы

    if VISUALIZE_SINGLE_GROUP_COMPARISON:
        visualize_visual_vs_collision_single_group(script_dir, TARGET_SINGLE_GROUP_FILE)
    elif VISUALIZE_AGGREGATED_COMPARISON_ПОДХОД1:
        धारा_метод_1_визуализировать_агрегированные_разделённые_геометрии(script_dir, AGGREGATED_PATTERNS)
    elif VISUALIZE_AGGREGATED_COMPARISON_ПОДХОД2:
        visualize_aggregated_visual_vs_collision(script_dir, AGGREGATED_PATTERNS)
    elif VISUALIZE_AGGREGATED_VISUAL:
        visualize_aggregated_wmo_points(script_dir) 
    elif VISUALIZE_AGGREGATED_COLLISION:
        visualize_aggregated_collision_geometry(script_dir)
    else:
        print("Ни один режим визуализации не выбран.")


