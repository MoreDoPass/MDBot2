#include "WMOParser.h"

#include <QLoggingCategory>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <set>
#include <tuple>

Q_LOGGING_CATEGORY(logWMOParser, "navmesh.wmoparser")

namespace NavMeshTool::WMO
{

namespace
{
// Helper function to transform a vertex using doodad definition (position, rotation, scale)
C3Vector transform_vertex(const C3Vector& vertex, const MODDData& doodad_def)
{
    // 1. Scale
    C3Vector scaled_vertex = {vertex.x * doodad_def.scale, vertex.y * doodad_def.scale, vertex.z * doodad_def.scale};

    // 2. Rotate (Quaternion to Matrix multiplication)
    const auto& rot = doodad_def.rotation;
    const float x2 = rot.x * rot.x;
    const float y2 = rot.y * rot.y;
    const float z2 = rot.z * rot.z;
    const float xy = rot.x * rot.y;
    const float xz = rot.x * rot.z;
    const float yz = rot.y * rot.z;
    const float wx = rot.w * rot.x;
    const float wy = rot.w * rot.y;
    const float wz = rot.w * rot.z;

    const C3Vector rotated_vertex = {
        scaled_vertex.x * (1.0f - 2.0f * y2 - 2.0f * z2) + scaled_vertex.y * (2.0f * xy - 2.0f * wz) +
            scaled_vertex.z * (2.0f * xz + 2.0f * wy),
        scaled_vertex.x * (2.0f * xy + 2.0f * wz) + scaled_vertex.y * (1.0f - 2.0f * x2 - 2.0f * z2) +
            scaled_vertex.z * (2.0f * yz - 2.0f * wx),
        scaled_vertex.x * (2.0f * xz - 2.0f * wy) + scaled_vertex.y * (2.0f * yz + 2.0f * wx) +
            scaled_vertex.z * (1.0f - 2.0f * x2 - 2.0f * y2)};

    // 3. Translate
    const C3Vector final_vertex = {rotated_vertex.x + doodad_def.position.x, rotated_vertex.y + doodad_def.position.y,
                                   rotated_vertex.z + doodad_def.position.z};

    return final_vertex;
}
}  // namespace

Parser::Parser() = default;

bool Parser::parse(const std::string& root_wmo_path)
{
    qCDebug(logWMOParser) << "Starting to parse WMO file:" << QString::fromStdString(root_wmo_path);

    m_root_data = parseRootFile(root_wmo_path);
    if (!m_root_data)
    {
        qCWarning(logWMOParser) << "Failed to parse root WMO file:" << QString::fromStdString(root_wmo_path);
        m_final_geometry = std::nullopt;
        return false;
    }

    WmoGeometry final_geometry;
    uint32_t current_vertex_offset = 0;

    std::string base_path = root_wmo_path;
    base_path = base_path.substr(0, base_path.length() - 4);  // Remove .wmo

    for (int i = 0; i < m_root_data->header.nGroups; ++i)
    {
        std::stringstream group_path_ss;
        group_path_ss << base_path << "_" << std::setw(3) << std::setfill('0') << i << ".wmo";
        const std::string group_path = group_path_ss.str();

        auto group_data_opt = parseGroupFile(group_path);
        if (!group_data_opt)
        {
            qCWarning(logWMOParser) << "Failed to parse group file, skipping:" << QString::fromStdString(group_path);
            continue;
        }

        auto& group_data = *group_data_opt;

        m_group_headers.push_back(group_data.header);

        if (group_data.vertices.empty() || group_data.indices.empty() || group_data.bsp_nodes.empty() ||
            group_data.bsp_refs.empty())
        {
            qCDebug(logWMOParser) << "Group file has no collision geometry, skipping:"
                                  << QString::fromStdString(group_path);
            continue;
        }

        std::set<std::tuple<uint16_t, uint16_t, uint16_t>> collision_triangles;

        for (const auto& node : group_data.bsp_nodes)
        {
            if (node.flags & 0x4)  // Is leaf node
            {
                for (int j = 0; j < node.nFaces; ++j)
                {
                    const uint16_t mobr_ref = group_data.bsp_refs[node.faceStart + j];
                    const uint32_t triangle_start_index = mobr_ref * 3;

                    if (triangle_start_index + 2 < group_data.indices.size())
                    {
                        std::tuple<uint16_t, uint16_t, uint16_t> triangle = {
                            group_data.indices[triangle_start_index], group_data.indices[triangle_start_index + 1],
                            group_data.indices[triangle_start_index + 2]};

                        uint16_t* p = &std::get<0>(triangle);
                        std::sort(p, p + 3);

                        collision_triangles.insert(triangle);
                    }
                }
            }
        }

        for (const auto& vertex : group_data.vertices)
        {
            final_geometry.vertices.push_back(vertex.position);
        }

        for (const auto& triangle : collision_triangles)
        {
            final_geometry.indices.push_back(std::get<0>(triangle) + current_vertex_offset);
            final_geometry.indices.push_back(std::get<1>(triangle) + current_vertex_offset);
            final_geometry.indices.push_back(std::get<2>(triangle) + current_vertex_offset);
        }

        current_vertex_offset += group_data.vertices.size();
        m_all_group_data.push_back(std::move(group_data));
    }

    // Doodad (M2) Geometry Processing
    if (!m_root_data->doodad_defs.empty() && !m_root_data->doodad_names_blob.empty())
    {
        for (const auto& doodad_def : m_root_data->doodad_defs)
        {
            if (doodad_def.name_offset >= m_root_data->doodad_names_blob.size()) continue;

            std::string m2_path(&m_root_data->doodad_names_blob[doodad_def.name_offset]);
            if (m2_path.empty()) continue;

            // The calling environment is responsible for making this path valid,
            // likely by extracting the file from MPQ archives into a location
            // where it can be resolved.
            auto m2_geom_opt = m_m2_parser.parse(m2_path);

            if (!m2_geom_opt || m2_geom_opt->vertices.empty() || m2_geom_opt->indices.empty())
            {
                qCDebug(logWMOParser) << "M2 Doodad has no collision geometry, skipping:"
                                      << QString::fromStdString(m2_path);
                continue;
            }

            auto& m2_geom = *m2_geom_opt;
            const uint32_t m2_vertex_count_before_add = final_geometry.vertices.size();

            for (const auto& local_vertex : m2_geom.vertices)
            {
                // The C3Vector from m2 needs to be converted to a wmo C3Vector
                const C3Vector wmo_vertex = {local_vertex.x, local_vertex.y, local_vertex.z};
                final_geometry.vertices.push_back(transform_vertex(wmo_vertex, doodad_def));
            }

            for (const auto& index : m2_geom.indices)
            {
                final_geometry.indices.push_back(index + m2_vertex_count_before_add);
            }
        }
    }

    qCDebug(logWMOParser) << "Successfully parsed WMO and its doodads. Total vertices:"
                          << final_geometry.vertices.size()
                          << "Total collision indices:" << final_geometry.indices.size();

    m_final_geometry = final_geometry;
    return true;
}

const std::optional<WmoGeometry>& Parser::get_geometry() const
{
    return m_final_geometry;
}

const std::vector<MOGPHeader>& Parser::get_group_headers() const
{
    return m_group_headers;
}

const std::vector<WmoGroupData>& Parser::get_all_group_data() const
{
    return m_all_group_data;
}

std::vector<GroupInfo> Parser::get_groups() const
{
    if (!m_root_data) return {};

    std::vector<GroupInfo> result;
    result.reserve(m_root_data->group_info.size());

    for (const auto& mogi_data : m_root_data->group_info)
    {
        GroupInfo info;
        info.flags = mogi_data.flags;
        info.bounding_box = mogi_data.bounding_box;

        if (mogi_data.name_offset != -1 && mogi_data.name_offset < m_root_data->group_names_blob.size())
        {
            info.name = std::string(&m_root_data->group_names_blob[mogi_data.name_offset]);
        }
        else
        {
            info.name = "N/A";
        }

        result.push_back(info);
    }

    return result;
}

const std::vector<C3Vector>& Parser::get_portal_vertices() const
{
    if (!m_root_data)
    {
        static const std::vector<C3Vector> empty_vec;
        return empty_vec;
    }
    return m_root_data->portal_vertices;
}

const std::vector<SMOPortalInfo>& Parser::get_portal_infos() const
{
    if (!m_root_data)
    {
        static const std::vector<SMOPortalInfo> empty_vec;
        return empty_vec;
    }
    return m_root_data->portal_info;
}

const std::vector<SMOPortalRef>& Parser::get_portal_refs() const
{
    if (!m_root_data)
    {
        static const std::vector<SMOPortalRef> empty_vec;
        return empty_vec;
    }
    return m_root_data->portal_refs;
}

const std::vector<SMODoodadSet>& Parser::get_doodad_sets() const
{
    if (!m_root_data)
    {
        static const std::vector<SMODoodadSet> empty_vec;
        return empty_vec;
    }
    return m_root_data->doodad_sets;
}

const std::vector<MODDData>& Parser::get_doodad_defs() const
{
    if (!m_root_data)
    {
        static const std::vector<MODDData> empty_vec;
        return empty_vec;
    }
    return m_root_data->doodad_defs;
}

const std::vector<char>& Parser::get_doodad_names_blob() const
{
    if (!m_root_data)
    {
        static const std::vector<char> empty_vec;
        return empty_vec;
    }
    return m_root_data->doodad_names_blob;
}

std::optional<WmoRootData> Parser::parseRootFile(const std::string& root_path) const
{
    std::ifstream file(root_path, std::ios::binary);
    if (!file)
    {
        qCWarning(logWMOParser) << "Could not open WMO root file:" << QString::fromStdString(root_path);
        return std::nullopt;
    }

    WmoRootData root_data;
    bool mver_found = false;
    bool mohd_found = false;

    while (file.peek() != EOF)
    {
        ChunkHeader header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (file.gcount() != sizeof(header)) break;

        const auto chunk_id = std::string(header.id, 4);
        const auto next_chunk_pos = static_cast<long long>(file.tellg()) + header.size;

        if (chunk_id == "REVM")  // MVER
        {
            MVERData mver_data;
            file.read(reinterpret_cast<char*>(&mver_data), sizeof(mver_data));
            if (mver_data.version != 17)
            {
                qCWarning(logWMOParser) << "Unsupported WMO version" << mver_data.version
                                        << "in root file:" << QString::fromStdString(root_path);
                return std::nullopt;
            }
            mver_found = true;
        }
        else if (chunk_id == "DHOM")  // MOHD
        {
            file.read(reinterpret_cast<char*>(&root_data.header), sizeof(root_data.header));
            mohd_found = true;
        }
        else if (chunk_id == "NGOM")  // MOGN
        {
            root_data.group_names_blob.resize(header.size);
            file.read(root_data.group_names_blob.data(), header.size);
        }
        else if (chunk_id == "IGOM")  // MOGI
        {
            root_data.group_info.resize(header.size / sizeof(MOGIData));
            file.read(reinterpret_cast<char*>(root_data.group_info.data()), header.size);
        }
        else if (chunk_id == "VPOM")  // MOPV
        {
            root_data.portal_vertices.resize(header.size / sizeof(C3Vector));
            file.read(reinterpret_cast<char*>(root_data.portal_vertices.data()), header.size);
        }
        else if (chunk_id == "TPOM")  // MOPT
        {
            root_data.portal_info.resize(header.size / sizeof(SMOPortalInfo));
            file.read(reinterpret_cast<char*>(root_data.portal_info.data()), header.size);
        }
        else if (chunk_id == "RPOM")  // MOPR
        {
            root_data.portal_refs.resize(header.size / sizeof(SMOPortalRef));
            file.read(reinterpret_cast<char*>(root_data.portal_refs.data()), header.size);
        }
        else if (chunk_id == "SDOM")  // MODS
        {
            root_data.doodad_sets.resize(header.size / sizeof(SMODoodadSet));
            file.read(reinterpret_cast<char*>(root_data.doodad_sets.data()), header.size);
        }
        else if (chunk_id == "NDOM")  // MODN
        {
            root_data.doodad_names_blob.resize(header.size);
            file.read(root_data.doodad_names_blob.data(), header.size);
        }
        else if (chunk_id == "DDOM")  // MODD
        {
            root_data.doodad_defs.resize(header.size / sizeof(MODDData));
            file.read(reinterpret_cast<char*>(root_data.doodad_defs.data()), header.size);
        }

        file.seekg(next_chunk_pos);
    }

    if (!mver_found || !mohd_found)
    {
        qCWarning(logWMOParser) << "Root WMO file is missing MVER or MOHD chunk:" << QString::fromStdString(root_path);
        return std::nullopt;
    }

    return root_data;
}

std::optional<WmoGroupData> Parser::parseGroupFile(const std::string& group_path) const
{
    std::ifstream file(group_path, std::ios::binary);
    if (!file)
    {
        qCWarning(logWMOParser) << "Could not open WMO group file:" << QString::fromStdString(group_path);
        return std::nullopt;
    }

    // MVER
    ChunkHeader mver_header;
    file.read(reinterpret_cast<char*>(&mver_header), sizeof(mver_header));
    if (std::string(mver_header.id, 4) != "REVM")
    {
        qCWarning(logWMOParser) << "Expected MVER chunk, but got" << mver_header.id
                                << "in file:" << QString::fromStdString(group_path);
        return std::nullopt;
    }

    MVERData mver_data;
    file.read(reinterpret_cast<char*>(&mver_data), sizeof(mver_data));
    if (mver_data.version != 17)
    {
        qCWarning(logWMOParser) << "Unsupported WMO version" << mver_data.version
                                << "in file:" << QString::fromStdString(group_path);
        return std::nullopt;
    }

    // MOGP
    ChunkHeader mogp_super_chunk_header;
    file.read(reinterpret_cast<char*>(&mogp_super_chunk_header), sizeof(mogp_super_chunk_header));
    if (std::string(mogp_super_chunk_header.id, 4) != "PGOM")
    {
        qCWarning(logWMOParser) << "Expected MOGP chunk, but got" << mogp_super_chunk_header.id
                                << "in file:" << QString::fromStdString(group_path);
        return std::nullopt;
    }

    const auto mogp_end_pos = static_cast<long long>(file.tellg()) + mogp_super_chunk_header.size;
    WmoGroupData group_data;
    file.read(reinterpret_cast<char*>(&group_data.header), sizeof(group_data.header));

    while (file.tellg() < mogp_end_pos)
    {
        ChunkHeader sub_chunk_header;
        file.read(reinterpret_cast<char*>(&sub_chunk_header), sizeof(sub_chunk_header));

        if (file.gcount() != sizeof(sub_chunk_header)) break;

        const auto sub_chunk_id = std::string(sub_chunk_header.id, 4);
        const auto next_chunk_pos = static_cast<long long>(file.tellg()) + sub_chunk_header.size;

        if (sub_chunk_id == "TVOM")  // MOVT - Vertex positions only
        {
            const auto num_vertices = sub_chunk_header.size / sizeof(C3Vector);
            group_data.vertices.resize(num_vertices);
            // We need to read only positions into a temporary buffer first
            std::vector<C3Vector> positions(num_vertices);
            file.read(reinterpret_cast<char*>(positions.data()), sub_chunk_header.size);
            for (size_t i = 0; i < num_vertices; ++i) group_data.vertices[i].position = positions[i];
        }
        else if (sub_chunk_id == "RNOM")  // MONR - Normals
        {
            const auto num_normals = sub_chunk_header.size / sizeof(C3Vector);
            if (num_normals == group_data.vertices.size())
            {
                std::vector<C3Vector> normals(num_normals);
                file.read(reinterpret_cast<char*>(normals.data()), sub_chunk_header.size);
                for (size_t i = 0; i < num_normals; ++i) group_data.vertices[i].normal = normals[i];
            }
        }
        else if (sub_chunk_id == "VTOM")  // MOTV - Texture Coordinates
        {
            const auto num_tex_coords = sub_chunk_header.size / sizeof(C2Vector);
            if (num_tex_coords == group_data.vertices.size())
            {
                std::vector<C2Vector> tex_coords(num_tex_coords);
                file.read(reinterpret_cast<char*>(tex_coords.data()), sub_chunk_header.size);
                for (size_t i = 0; i < num_tex_coords; ++i) group_data.vertices[i].tex_coords = tex_coords[i];
            }
        }
        else if (sub_chunk_id == "YPOM")  // MOPY
        {
            group_data.polygons.resize(sub_chunk_header.size / sizeof(SMOPoly));
            file.read(reinterpret_cast<char*>(group_data.polygons.data()), sub_chunk_header.size);
        }
        else if (sub_chunk_id == "IVOM")  // MOVI
        {
            group_data.indices.resize(sub_chunk_header.size / sizeof(uint16_t));
            file.read(reinterpret_cast<char*>(group_data.indices.data()), sub_chunk_header.size);
        }
        else if (sub_chunk_id == "NBOM")  // MOBN
        {
            group_data.bsp_nodes.resize(sub_chunk_header.size / sizeof(CAaBspNode));
            file.read(reinterpret_cast<char*>(group_data.bsp_nodes.data()), sub_chunk_header.size);
        }
        else if (sub_chunk_id == "RBOM")  // MOBR
        {
            group_data.bsp_refs.resize(sub_chunk_header.size / sizeof(uint16_t));
            file.read(reinterpret_cast<char*>(group_data.bsp_refs.data()), sub_chunk_header.size);
        }

        file.seekg(next_chunk_pos);
    }

    return group_data;
}

}  // namespace NavMeshTool::WMO
