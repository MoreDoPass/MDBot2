#include "TerrainProcessor.h"
#include <array>

namespace
{
// Константы для расчетов геометрии, перенесенные из NavMeshGenerator.
// Они необходимы для правильного расчета координат вершин ландшафта.
constexpr float TILE_SIZE = 1600.0f / 3.0f;           // ~533.33333 ярдов
constexpr float MCNK_SIZE_UNITS = TILE_SIZE / 16.0f;  // ~33.33333 ярдов
constexpr float MAP_CHUNK_SIZE = TILE_SIZE * 32.0f;   // 17066.666
}  // namespace

namespace NavMesh
{
namespace Processors
{

TerrainProcessor::TerrainProcessor() = default;

void TerrainProcessor::process(const NavMeshTool::ADT::ADTData& adtData, int row, int col,
                               std::vector<float>& worldVertices, std::vector<int>& worldTriangleIndices)
{
    if (m_terrainTileIndices.empty())
    {
        buildTerrainTileIndices();
    }

    for (const auto& mcnk : adtData.mcnkChunks)
    {
        if (mcnk.mcvtData.heights.empty())
        {
            continue;
        }

        const size_t vertexOffset = worldVertices.size() / 3;

        const int pos_x = (col * 16) + mcnk.header.indexX;
        const int pos_y = (row * 16) + mcnk.header.indexY;
        const int neighbor_chunk_index_x = pos_x + 1;
        const int neighbor_chunk_index_y = pos_y + 1;

        std::array<float, 9> VertexYCoordsCache_South;
        std::array<float, 9> VertexXCoordsCache_West;

        const float final_world_Y = MAP_CHUNK_SIZE - (static_cast<float>(pos_x) * MCNK_SIZE_UNITS);
        const float final_world_X = MAP_CHUNK_SIZE - (static_cast<float>(pos_y) * MCNK_SIZE_UNITS);

        VertexYCoordsCache_South[0] = final_world_Y;
        VertexXCoordsCache_West[0] = final_world_X;

        const float step = MCNK_SIZE_UNITS / 8.0f;
        for (int i = 1; i < 8; ++i)
        {
            VertexYCoordsCache_South[i] = final_world_Y - (step * i);
            VertexXCoordsCache_West[i] = final_world_X - (step * i);
        }

        VertexYCoordsCache_South[8] = MAP_CHUNK_SIZE - (static_cast<float>(neighbor_chunk_index_x) * MCNK_SIZE_UNITS);
        VertexXCoordsCache_West[8] = MAP_CHUNK_SIZE - (static_cast<float>(neighbor_chunk_index_y) * MCNK_SIZE_UNITS);

        const float world_z_base = mcnk.header.ypos;
        size_t mcvt_ptr = 0;

        for (int j = 0; j < 9; ++j)
        {
            for (int i = 0; i < 9; ++i)
            {
                const float world_x = VertexXCoordsCache_West[j];
                const float world_y = VertexYCoordsCache_South[i];
                const float world_z = world_z_base + mcnk.mcvtData.heights[mcvt_ptr + i];

                worldVertices.push_back(world_x);
                worldVertices.push_back(world_y);
                worldVertices.push_back(world_z);
            }
            mcvt_ptr += 9;

            if (j < 8)
            {
                for (int i = 0; i < 8; ++i)
                {
                    const float world_x = VertexXCoordsCache_West[j] - (step / 2.0f);
                    const float world_y = VertexYCoordsCache_South[i] - (step / 2.0f);
                    const float world_z = world_z_base + mcnk.mcvtData.heights[mcvt_ptr + i];

                    worldVertices.push_back(world_x);
                    worldVertices.push_back(world_y);
                    worldVertices.push_back(world_z);
                }
                mcvt_ptr += 8;
            }
        }

        for (int index : m_terrainTileIndices)
        {
            worldTriangleIndices.push_back(static_cast<int>(vertexOffset + index));
        }
    }
}

void TerrainProcessor::buildTerrainTileIndices()
{
    m_terrainTileIndices.clear();
    m_terrainTileIndices.reserve(8 * 8 * 4 * 3);

    for (int i = 0; i < 8; ++i)
    {
        for (int j = 0; j < 8; ++j)
        {
            const int outer_grid_stride = 17;

            const int idx_A = (i * outer_grid_stride) + j;
            const int idx_B = idx_A + 1;
            const int idx_X = (i * outer_grid_stride) + 9 + j;
            const int idx_C = idx_A + outer_grid_stride;
            const int idx_D = idx_B + outer_grid_stride;

            m_terrainTileIndices.push_back(idx_X);
            m_terrainTileIndices.push_back(idx_A);
            m_terrainTileIndices.push_back(idx_C);

            m_terrainTileIndices.push_back(idx_X);
            m_terrainTileIndices.push_back(idx_B);
            m_terrainTileIndices.push_back(idx_A);

            m_terrainTileIndices.push_back(idx_X);
            m_terrainTileIndices.push_back(idx_D);
            m_terrainTileIndices.push_back(idx_B);

            m_terrainTileIndices.push_back(idx_X);
            m_terrainTileIndices.push_back(idx_C);
            m_terrainTileIndices.push_back(idx_D);
        }
    }
}

}  // namespace Processors
}  // namespace NavMesh
