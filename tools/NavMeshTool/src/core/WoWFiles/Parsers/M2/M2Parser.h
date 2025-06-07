#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wow_files::m2
{

struct C3Vector
{
    float x, y, z;
};

struct CAaBox
{
    C3Vector min_corner;
    C3Vector max_corner;
};

#pragma pack(push, 1)
struct M2Header
{
    char magic[4];                        // 0x00: "MD20"
    uint32_t version;                     // 0x04: Version (264 for WotLK).
    uint32_t length_model_name;           // 0x08
    uint32_t offset_model_name;           // 0x0C
    uint32_t model_flags;                 // 0x10: GlobalModelFlags
    uint32_t num_global_sequences;        // 0x14
    uint32_t offset_global_sequences;     // 0x18
    uint32_t num_animations;              // 0x1C
    uint32_t offset_animations;           // 0x20
    uint32_t num_animation_lookup;        // 0x24
    uint32_t offset_animation_lookup;     // 0x28
    uint32_t num_bones;                   // 0x2C
    uint32_t offset_bones;                // 0x30
    uint32_t num_key_bone_lookup;         // 0x34
    uint32_t offset_key_bone_lookup;      // 0x38
    uint32_t num_vertices;                // 0x3C
    uint32_t offset_vertices;             // 0x40
    uint32_t num_views;                   // 0x44
    uint32_t num_colors;                  // 0x48
    uint32_t offset_colors;               // 0x4C
    uint32_t num_textures;                // 0x50
    uint32_t offset_textures;             // 0x54
    uint32_t num_transparency;            // 0x58
    uint32_t offset_transparency;         // 0x5C
    uint32_t num_texture_animations;      // 0x60
    uint32_t offset_texture_animations;   // 0x64
    uint32_t num_texture_replace;         // 0x68
    uint32_t offset_texture_replace;      // 0x6C
    uint32_t num_materials;               // 0x70
    uint32_t offset_materials;            // 0x74
    uint32_t num_bone_combos;             // 0x78
    uint32_t offset_bone_combos;          // 0x7C
    uint32_t num_texture_combos;          // 0x80
    uint32_t offset_texture_combos;       // 0x84
    uint32_t num_tex_coord_combos;        // 0x88
    uint32_t offset_tex_coord_combos;     // 0x8C
    uint32_t num_transparency_lookup;     // 0x90
    uint32_t offset_transparency_lookup;  // 0x94
    uint32_t num_tex_anim_lookup;         // 0x98
    uint32_t offset_tex_anim_lookup;      // 0x9C
    CAaBox bounding_box;                  // 0xA0 - 0xB7
    float bounding_sphere_radius;         // 0xB8 - 0xBB
    CAaBox collision_box;                 // 0xBC - 0xD3
    float collision_sphere_radius;        // 0xD4 - 0xD7
    uint32_t num_collision_indices;       // 0xD8
    uint32_t offset_collision_indices;    // 0xDC
    uint32_t num_collision_vertices;      // 0xE0
    uint32_t offset_collision_vertices;   // 0xE4
    uint32_t num_collision_normals;       // 0xE8
    uint32_t offset_collision_normals;    // 0xEC
    uint32_t num_attachments;             // 0xF0
    uint32_t offset_attachments;          // 0xF4
    uint32_t num_attachment_lookup;       // 0xF8
    uint32_t offset_attachment_lookup;    // 0xFC
    uint32_t num_events;                  // 0x100
    uint32_t offset_events;               // 0x104
};
#pragma pack(pop)

static_assert(sizeof(M2Header) == 264, "M2_Header_WotLK size must be 264 bytes");

struct CollisionGeometry
{
    std::vector<C3Vector> vertices;
    std::vector<uint16_t> indices;
    std::vector<C3Vector> normals;
};

class M2Parser
{
   public:
    M2Parser() = default;

    std::optional<CollisionGeometry> parse(const std::string& file_path) const;
};

}  // namespace wow_files::m2
