#pragma once

#include <vector>
#include <string>
#include <optional>
#include <functional>
#include <cstdint>

namespace NavMeshTool::WMO
{
// Common structures based on WMO format documentation

#pragma pack(push, 1)
struct C3Vector
{
    float x, y, z;
};

struct CAaBox
{
    C3Vector min;
    C3Vector max;
};

struct ChunkHeader
{
    char id[4];
    uint32_t size;
};

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
    uint16_t padding_or_lod_count;
};

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

struct SMOGroupInfo
{
    uint32_t flags;
    CAaBox bounding_box;
    int32_t name_offset;
};

struct SMOVertex
{
    C3Vector position;
    C3Vector normal;
};

struct SMOPoly
{
    uint8_t flags;
    uint8_t material_id;
};

struct CAaBspNode
{
    uint16_t flags;
    int16_t negChild;
    int16_t posChild;
    uint16_t nFaces;
    uint32_t faceStart;
    float planeDist;
};

struct MODDData
{
    uint32_t name_offset;
    C3Vector position;
    float rotation[4];  // Quaternion
    float scale;
    uint8_t color[4];
};

struct SMODoodadSet
{
    char name[20];
    uint32_t first_instance_index;
    uint32_t num_doodads;
    uint32_t unused;
};

struct SMOPortalInfo
{
    uint16_t start_vertex_index;
    uint16_t count;
    C3Vector normal;
    float unknown_or_distance;
};

struct SMOPortalRef
{
    uint16_t portal_index;
    uint16_t group_index;
    int16_t side;
    uint16_t filler;
};
#pragma pack(pop)

struct WmoGroupData
{
    bool is_parsed = false;
    MOGPHeader header;
    std::vector<SMOVertex> vertices;
    std::vector<uint16_t> indices;
    std::vector<SMOPoly> polygons;
    std::vector<CAaBspNode> bsp_nodes;
    std::vector<uint16_t> bsp_refs;
};

struct WmoData
{
    MOHDData header;
    std::vector<char> group_names_blob;
    std::vector<SMOGroupInfo> group_info;
    std::vector<SMODoodadSet> doodad_sets;
    std::vector<char> doodad_names_blob;
    std::vector<MODDData> doodad_defs;
    std::vector<C3Vector> portal_vertices;
    std::vector<SMOPortalInfo> portal_infos;
    std::vector<SMOPortalRef> portal_refs;
    std::vector<WmoGroupData> groups;

    // Combined geometry
    std::vector<C3Vector> vertices;
    std::vector<uint32_t> indices;
};

using FileProvider = std::function<std::optional<std::vector<unsigned char>>(const std::string&)>;

class Parser
{
   public:
    std::optional<WmoData> parse(const std::string& rootWmoName, const std::vector<unsigned char>& rootWmoBuffer,
                                 const FileProvider& fileProvider) const;
};

}  // namespace NavMeshTool::WMO
