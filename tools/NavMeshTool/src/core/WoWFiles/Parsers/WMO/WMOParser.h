#pragma once

#include "core/WoWFiles/Parsers/M2/M2Parser.h"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace NavMeshTool::WMO
{

#pragma pack(push, 1)

struct C3Vector
{
    float x, y, z;
};

struct C4Vector
{
    float x, y, z, w;
};

struct C2Vector
{
    float u, v;
};

// Using C4Vector for CQuaternion for simplicity in reading.
using CQuaternion = C4Vector;

struct CAaBox
{
    C3Vector min;
    C3Vector max;
};

// Generic chunk header
struct ChunkHeader
{
    char id[4];  // Reversed in file, e.g., "REVM" for MVER
    uint32_t size;
};

// MVER Chunk Data
struct MVERData
{
    uint32_t version;
};

// MOHD Chunk Data (Root WMO)
struct MOHDData
{
    uint32_t nTextures;
    uint32_t nGroups;
    uint32_t nPortals;
    uint32_t nLights;
    uint32_t nDoodadNames;
    uint32_t nDoodadDefs;
    uint32_t nDoodadSets;
    uint32_t ambColor;
    uint32_t wmoID;
    CAaBox bounding_box;
    uint16_t flags;
    uint16_t padding;
};

// MOGI Chunk Data (Root WMO)
struct MOGIData
{
    uint32_t flags;
    CAaBox bounding_box;
    int32_t name_offset;
};

// MODD Chunk Data (Root WMO)
struct MODDData
{
    uint32_t name_offset;
    C3Vector position;
    CQuaternion rotation;
    float scale;
    uint32_t color;
};

// MOPT Chunk Data (Root WMO)
struct SMOPortalInfo
{
    uint16_t start_vertex_index;
    uint16_t count;
    C3Vector normal;
    float unknown_or_distance;
};

// MOPR Chunk Data (Root WMO)
struct SMOPortalRef
{
    uint16_t portal_index;
    uint16_t group_index;
    int16_t side;
    uint16_t filler;
};

// MODS Chunk Data (Root WMO)
struct SMODoodadSet
{
    char name[20];
    uint32_t first_instance_index;
    uint32_t num_doodads;
    uint32_t unused;
};

// MOGP Chunk Header (Group WMO)
struct MOGPHeader
{
    uint32_t groupNameOffset;
    uint32_t descriptiveGroupNameOffset;
    uint32_t flags;
    CAaBox bounding_box;
    uint16_t portal_start_index;
    uint16_t portal_count;
    uint16_t transBatchCount;
    uint16_t interiorBatchCount;
    uint16_t exteriorBatchCount;
    uint16_t padding_or_batch_type_d;
    uint8_t fogIds[4];
    uint32_t liquid_type_or_flags;
    uint32_t wmo_group_id;
    uint32_t wotlk_flags2;
    uint32_t wotlk_unk_padding;
};

// MOVT Chunk Vertex Data (Group WMO)
struct SMOVertex
{
    C3Vector position;
    C3Vector normal;
    C2Vector tex_coords;
};

// MOPY Chunk Polygon Data (Group WMO)
struct SMOPoly
{
    uint8_t flags;
    uint8_t material_id;
};

// MOBN Chunk BSP Node (Group WMO)
struct CAaBspNode
{
    uint16_t flags;
    int16_t negChild;
    int16_t posChild;
    uint16_t nFaces;
    uint32_t faceStart;
    float planeDist;
};

#pragma pack(pop)

// Holds the raw data parsed from a single WMO group file
struct WmoGroupData
{
    MOGPHeader header;
    std::vector<SMOVertex> vertices;
    std::vector<uint16_t> indices;
    std::vector<SMOPoly> polygons;
    std::vector<CAaBspNode> bsp_nodes;
    std::vector<uint16_t> bsp_refs;
};

// Holds the essential data parsed from the root WMO file
struct WmoRootData
{
    MOHDData header;
    std::vector<MOGIData> group_info;
    std::vector<char> group_names_blob;      // MOGN
    std::vector<C3Vector> portal_vertices;   // MOPV
    std::vector<SMOPortalInfo> portal_info;  // MOPT
    std::vector<SMOPortalRef> portal_refs;   // MOPR
    std::vector<SMODoodadSet> doodad_sets;   // MODS
    std::vector<char> doodad_names_blob;     // MODN
    std::vector<MODDData> doodad_defs;       // MODD
};

struct WmoGeometry
{
    std::vector<C3Vector> vertices;
    std::vector<uint32_t> indices;
};

// A friendly structure combining MOGI data with the resolved group name
struct GroupInfo
{
    std::string name;
    uint32_t flags;
    CAaBox bounding_box;
};

class Parser
{
   public:
    Parser();

    // The main parse function. Returns true on success.
    // After a successful call, you can retrieve geometry and metadata.
    bool parse(const std::string& root_wmo_path);

    // Retrieves the combined geometry of all parsed WMO groups and doodads.
    const std::optional<WmoGeometry>& get_geometry() const;

    // Retrieves metadata for all groups found in the root WMO.
    std::vector<GroupInfo> get_groups() const;

    // Retrieves the MOGP headers for all successfully parsed group files.
    const std::vector<MOGPHeader>& get_group_headers() const;

    // Retrieves the raw data for all successfully parsed group files.
    const std::vector<WmoGroupData>& get_all_group_data() const;

    const std::vector<C3Vector>& get_portal_vertices() const;
    const std::vector<SMOPortalInfo>& get_portal_infos() const;
    const std::vector<SMOPortalRef>& get_portal_refs() const;

    const std::vector<SMODoodadSet>& get_doodad_sets() const;
    const std::vector<MODDData>& get_doodad_defs() const;
    const std::vector<char>& get_doodad_names_blob() const;

   private:
    NavMeshTool::M2::Parser m_m2_parser;
    std::optional<WmoRootData> m_root_data;
    std::optional<WmoGeometry> m_final_geometry;
    std::vector<MOGPHeader> m_group_headers;
    std::vector<WmoGroupData> m_all_group_data;

    // Parses the root WMO file and returns its structural data.
    std::optional<WmoRootData> parseRootFile(const std::string& root_path) const;

    // Parses a single WMO group file and returns its raw geometric data.
    std::optional<WmoGroupData> parseGroupFile(const std::string& group_path) const;
};

}  // namespace NavMeshTool::WMO
