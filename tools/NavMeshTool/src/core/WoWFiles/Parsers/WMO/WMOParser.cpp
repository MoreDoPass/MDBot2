#include "WMOParser.h"
#include "core/WoWFiles/Parsers/M2/M2Parser.h"

#include <QLoggingCategory>
#include <cstring>
#include <vector>
#include <set>
#include <tuple>
#include <algorithm>
#include <filesystem>
#include <sstream>

Q_LOGGING_CATEGORY(logWMOParser, "navmesh.wmoparser")

namespace NavMeshTool::WMO
{

namespace
{
/// <summary>
/// Safely reads a chunk of data from a buffer.
/// </summary>
/// <param name="ptr">Pointer to the current position in the buffer.</param>
/// <param name="remainingSize">Remaining size of the buffer.</param>
/// <param name="chunkSize">The size of the data chunk to read.</param>
/// <param name="destination">Vector to store the read data.</param>
/// <returns>True if the chunk was read successfully, false otherwise.</returns>
template <typename T>
bool readChunk(const unsigned char*& ptr, size_t& remainingSize, size_t chunkSize, std::vector<T>& destination)
{
    if (remainingSize < chunkSize)
    {
        qCWarning(logWMOParser) << "Cannot read chunk: not enough data. Remaining:" << remainingSize
                                << "Requested:" << chunkSize;
        return false;
    }

    if (chunkSize > 0 && chunkSize % sizeof(T) != 0)
    {
        qCWarning(logWMOParser) << "Chunk size" << chunkSize << "is not a multiple of data type size" << sizeof(T);
        // Do not fail here, just warn. Some chunks can have padding.
        // Let's adjust to the largest multiple.
        chunkSize = (chunkSize / sizeof(T)) * sizeof(T);
    }

    size_t num_elements = (chunkSize == 0) ? 0 : chunkSize / sizeof(T);
    destination.resize(num_elements);

    if (chunkSize > 0) memcpy(destination.data(), ptr, chunkSize);

    return true;
}

// Helper to read raw data into a single struct
template <typename T>
bool readData(const unsigned char*& ptr, size_t& remainingSize, T& destination)
{
    if (remainingSize < sizeof(T))
    {
        return false;
    }
    memcpy(&destination, ptr, sizeof(T));
    return true;
}

// Helper function to transform a vertex using doodad definition (position, rotation, scale)
C3Vector transformVertex(const C3Vector& vertex, const MODDData& doodad_def)
{
    C3Vector scaled_vertex = {vertex.x * doodad_def.scale, vertex.y * doodad_def.scale, vertex.z * doodad_def.scale};

    const auto& rot = doodad_def.rotation;
    // The quaternion components are stored as an array: {x, y, z, w}
    const float x = rot[0];
    const float y = rot[1];
    const float z = rot[2];
    const float w = rot[3];

    const float x2 = x * x, y2 = y * y, z2 = z * z;
    const float xy = x * y, xz = x * z, yz = y * z;
    const float wx = w * x, wy = w * y, wz = w * z;

    const C3Vector rotated_vertex = {
        scaled_vertex.x * (1.0f - 2.0f * y2 - 2.0f * z2) + scaled_vertex.y * (2.0f * xy - 2.0f * wz) +
            scaled_vertex.z * (2.0f * xz + 2.0f * wy),
        scaled_vertex.x * (2.0f * xy + 2.0f * wz) + scaled_vertex.y * (1.0f - 2.0f * x2 - 2.0f * z2) +
            scaled_vertex.z * (2.0f * yz - 2.0f * wx),
        scaled_vertex.x * (2.0f * xz - 2.0f * wy) + scaled_vertex.y * (2.0f * yz + 2.0f * wx) +
            scaled_vertex.z * (1.0f - 2.0f * x2 - 2.0f * y2)};

    return {rotated_vertex.x + doodad_def.position.x, rotated_vertex.y + doodad_def.position.y,
            rotated_vertex.z + doodad_def.position.z};
}

bool parseGroupWmo(const std::vector<unsigned char>& buffer, WmoGroupData& outGroupData)
{
    const unsigned char* currentPtr = buffer.data();
    size_t remainingSize = buffer.size();

    // Skip MVER
    currentPtr += 12;
    remainingSize -= 12;

    ChunkHeader mogpSuperChunkHeader;
    if (!readData(currentPtr, remainingSize, mogpSuperChunkHeader) || memcmp(mogpSuperChunkHeader.id, "PGOM", 4) != 0)
        return false;

    currentPtr += sizeof(ChunkHeader);
    remainingSize -= sizeof(ChunkHeader);

    const unsigned char* mogpEndPtr = currentPtr + mogpSuperChunkHeader.size;
    if (!readData(currentPtr, remainingSize, outGroupData.header)) return false;

    currentPtr += sizeof(MOGPHeader);
    remainingSize -= sizeof(MOGPHeader);

    while (currentPtr < mogpEndPtr && remainingSize >= sizeof(ChunkHeader))
    {
        ChunkHeader subChunkHeader;
        if (!readData(currentPtr, remainingSize, subChunkHeader)) break;

        currentPtr += sizeof(ChunkHeader);
        remainingSize -= sizeof(ChunkHeader);

        const unsigned char* subChunkDataPtr = currentPtr;
        size_t subChunkDataRemainingSize = subChunkHeader.size;

        if (memcmp(subChunkHeader.id, "TVOM", 4) == 0)  // MOVT
        {
            const auto num_vertices = subChunkHeader.size / sizeof(C3Vector);
            outGroupData.vertices.resize(num_vertices);
            std::vector<C3Vector> positions;
            if (!readChunk(subChunkDataPtr, subChunkDataRemainingSize, subChunkHeader.size, positions)) return false;
            for (size_t i = 0; i < num_vertices; ++i) outGroupData.vertices[i].position = positions[i];
        }
        else if (memcmp(subChunkHeader.id, "RNOM", 4) == 0)  // MONR
        {
            std::vector<C3Vector> normals;
            if (!readChunk(subChunkDataPtr, subChunkDataRemainingSize, subChunkHeader.size, normals)) return false;
            for (size_t i = 0; i < normals.size(); ++i) outGroupData.vertices[i].normal = normals[i];
        }
        else if (memcmp(subChunkHeader.id, "YPOM", 4) == 0)  // MOPY
        {
            if (!readChunk(subChunkDataPtr, subChunkDataRemainingSize, subChunkHeader.size, outGroupData.polygons))
                return false;
        }
        else if (memcmp(subChunkHeader.id, "IVOM", 4) == 0)  // MOVI
        {
            if (!readChunk(subChunkDataPtr, subChunkDataRemainingSize, subChunkHeader.size, outGroupData.indices))
                return false;
        }
        else if (memcmp(subChunkHeader.id, "NBOM", 4) == 0)  // MOBN
        {
            if (!readChunk(subChunkDataPtr, subChunkDataRemainingSize, subChunkHeader.size, outGroupData.bsp_nodes))
                return false;
        }
        else if (memcmp(subChunkHeader.id, "RBOM", 4) == 0)  // MOBR
        {
            if (!readChunk(subChunkDataPtr, subChunkDataRemainingSize, subChunkHeader.size, outGroupData.bsp_refs))
                return false;
        }

        currentPtr += subChunkHeader.size;
        remainingSize -= subChunkHeader.size;
    }
    return true;
}

bool parseRootWmo(const std::vector<unsigned char>& buffer, WmoData& outData)
{
    const unsigned char* currentPtr = buffer.data();
    size_t remainingSize = buffer.size();

    while (remainingSize >= sizeof(ChunkHeader))
    {
        ChunkHeader header;
        if (!readData(currentPtr, remainingSize, header)) break;

        currentPtr += sizeof(ChunkHeader);
        remainingSize -= sizeof(ChunkHeader);

        if (remainingSize < header.size) return false;

        const unsigned char* chunk_data_ptr = currentPtr;
        size_t chunk_data_remaining_size = header.size;

        if (memcmp(header.id, "DHOM", 4) == 0)
        {
            if (header.size != sizeof(MOHDData)) return false;
            memcpy(&outData.header, chunk_data_ptr, sizeof(MOHDData));
        }
        else if (memcmp(header.id, "NGOM", 4) == 0)
        {
            outData.group_names_blob.assign(chunk_data_ptr, chunk_data_ptr + header.size);
        }
        else if (memcmp(header.id, "IGOM", 4) == 0)
        {
            if (!readChunk(chunk_data_ptr, chunk_data_remaining_size, header.size, outData.group_info)) return false;
        }
        else if (memcmp(header.id, "SDOM", 4) == 0)
        {
            if (!readChunk(chunk_data_ptr, chunk_data_remaining_size, header.size, outData.doodad_sets)) return false;
        }
        else if (memcmp(header.id, "NDOM", 4) == 0)
        {
            outData.doodad_names_blob.assign(chunk_data_ptr, chunk_data_ptr + header.size);
        }
        else if (memcmp(header.id, "DDOM", 4) == 0)
        {
            if (!readChunk(chunk_data_ptr, chunk_data_remaining_size, header.size, outData.doodad_defs)) return false;
        }
        else if (memcmp(header.id, "VPOM", 4) == 0)  // MOPV
        {
            if (!readChunk(chunk_data_ptr, chunk_data_remaining_size, header.size, outData.portal_vertices))
                return false;
        }
        else if (memcmp(header.id, "TPOM", 4) == 0)  // MOPT
        {
            if (!readChunk(chunk_data_ptr, chunk_data_remaining_size, header.size, outData.portal_infos)) return false;
        }
        else if (memcmp(header.id, "RPOM", 4) == 0)  // MOPR
        {
            if (!readChunk(chunk_data_ptr, chunk_data_remaining_size, header.size, outData.portal_refs)) return false;
        }

        currentPtr += header.size;
        remainingSize -= header.size;
    }
    return true;
}
}  // namespace

/// <summary>
/// Parses the root WMO buffer to extract metadata and chunk information. This is a free function.
/// </summary>
std::optional<WmoData> Parser::parse(const std::string& rootWmoName, const std::vector<unsigned char>& rootWmoBuffer,
                                     const FileProvider& fileProvider) const
{
    qCInfo(logWMOParser) << "Starting WMO parsing for" << QString::fromStdString(rootWmoName)
                         << ". Buffer size:" << rootWmoBuffer.size();

    if (rootWmoBuffer.size() < sizeof(ChunkHeader))
    {
        qCWarning(logWMOParser) << "Initial buffer size is too small for even a single chunk header.";
        return std::nullopt;
    }

    WmoData wmoData;

    if (!parseRootWmo(rootWmoBuffer, wmoData))
    {
        qCWarning(logWMOParser) << "Failed to parse root WMO buffer.";
        return std::nullopt;
    }

    wmoData.groups.resize(wmoData.header.nGroups);
    const std::string wmo_base_name = std::filesystem::path(rootWmoName).stem().string();

    // Parse group files
    for (uint32_t i = 0; i < wmoData.header.nGroups; ++i)
    {
        std::stringstream group_filename_ss;
        group_filename_ss << wmo_base_name << "_" << std::setw(3) << std::setfill('0') << i << ".wmo";
        const std::string group_name = group_filename_ss.str();

        auto groupBufferOpt = fileProvider(group_name);

        if (!groupBufferOpt)
        {
            qCWarning(logWMOParser) << "Could not get group WMO file:" << QString::fromStdString(group_name);
            continue;
        }

        WmoGroupData& groupData = wmoData.groups[i];
        groupData.is_parsed = parseGroupWmo(*groupBufferOpt, groupData);

        if (groupData.is_parsed)
        {
            // Используем ТОЛЬКО BSP-дерево как единственный источник информации о коллизии.
            // Все группы без явного BSP-дерева будут проигнорированы.
            if (!groupData.bsp_nodes.empty() && !groupData.bsp_refs.empty())
            {
                // Шаг 1: Получаем "грязный" список полигонов из BSP
                std::set<uint16_t> bsp_triangle_indices;
                for (const auto& node : groupData.bsp_nodes)
                {
                    if (node.flags & 0x4)  // Листовой узел
                    {
                        for (uint32_t j = 0; j < node.nFaces; ++j)
                        {
                            bsp_triangle_indices.insert(groupData.bsp_refs[node.faceStart + j]);
                        }
                    }
                }

                // Шаг 2: Применяем второй, уточняющий фильтр по флагам MOPY
                std::vector<uint16_t> final_triangle_indices;
                for (const auto& tri_index : bsp_triangle_indices)
                {
                    // Если данных о флагах нет (на всякий случай), или флаг "no-walk" (0x04) НЕ установлен,
                    // то этот полигон нам подходит.
                    if (groupData.polygons.empty() ||
                        (tri_index < groupData.polygons.size() && !(groupData.polygons[tri_index].flags & 0x04)))
                    {
                        final_triangle_indices.push_back(tri_index);
                    }
                }

                // Шаг 3: Собираем геометрию только из отфильтрованных полигонов
                std::map<uint16_t, uint32_t> index_map;  // Карта старых индексов вершин на новые
                for (const auto& tri_index : final_triangle_indices)
                {
                    // Убеждаемся, что мы не выходим за пределы массива индексов
                    if ((tri_index * 3 + 2) >= groupData.indices.size()) continue;

                    // Для каждой из 3-х вершин треугольника
                    for (int v_num = 0; v_num < 3; ++v_num)
                    {
                        uint16_t old_vertex_index = groupData.indices[tri_index * 3 + v_num];

                        // Если вершина еще не была добавлена, добавляем ее и сохраняем ее новый индекс
                        if (index_map.find(old_vertex_index) == index_map.end())
                        {
                            wmoData.vertices.push_back(groupData.vertices[old_vertex_index].position);
                            index_map[old_vertex_index] = static_cast<uint32_t>(wmoData.vertices.size() - 1);
                        }
                    }

                    // Добавляем индексы треугольника с новыми, переназначенными индексами вершин
                    wmoData.indices.push_back(index_map.at(groupData.indices[tri_index * 3 + 0]));
                    wmoData.indices.push_back(index_map.at(groupData.indices[tri_index * 3 + 1]));
                    wmoData.indices.push_back(index_map.at(groupData.indices[tri_index * 3 + 2]));
                }
            }
        }
    }

    // Parse M2 Doodads
    M2::Parser m2Parser;
    for (const auto& doodadDef : wmoData.doodad_defs)
    {
        if (doodadDef.name_offset >= wmoData.doodad_names_blob.size()) continue;

        std::string doodadName(&wmoData.doodad_names_blob[doodadDef.name_offset]);
        auto m2BufferOpt = fileProvider(doodadName);

        if (!m2BufferOpt) continue;

        auto m2GeomOpt = m2Parser.parse(*m2BufferOpt);
        if (m2GeomOpt && !m2GeomOpt->vertices.empty())
        {
            uint32_t vertexOffset = static_cast<uint32_t>(wmoData.vertices.size());
            for (const auto& v : m2GeomOpt->vertices)
            {
                const WMO::C3Vector wmo_vertex = {v.x, v.y, v.z};
                wmoData.vertices.push_back(transformVertex(wmo_vertex, doodadDef));
            }
            for (const auto& i : m2GeomOpt->indices) wmoData.indices.push_back(i + vertexOffset);
        }
    }

    qCDebug(logWMOParser) << "Successfully parsed root WMO. Groups to load:" << wmoData.header.nGroups;
    return wmoData;
}

}  // namespace NavMeshTool::WMO
