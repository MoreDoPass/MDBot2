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

        // --- ИЗМЕНЕНО: Умная генерация индексов с учетом дыр ---
        // Вместо слепого копирования шаблона, итерируемся по сетке 8x8.
        const uint16_t holes_mask = mcnk.header.holes_low_res;

        for (int i = 0; i < 8; ++i)  // i - строка в сетке 8x8
        {
            for (int j = 0; j < 8; ++j)  // j - колонка в сетке 8x8
            {
                // Определяем, какому биту из сетки 4x4 соответствует наш квадрат 8x8
                const int hole_y = i / 2;
                const int hole_x = j / 2;
                const int bit_index = hole_y * 4 + hole_x;
                const bool is_hole = (holes_mask >> bit_index) & 1;

                // Если это не дыра, то добавляем 4 треугольника, составляющих квадрат.
                if (!is_hole)
                {
                    const int outer_grid_stride = 17;

                    const int idx_A = (i * outer_grid_stride) + j;
                    const int idx_B = idx_A + 1;
                    const int idx_X = (i * outer_grid_stride) + 9 + j;  // Центральная вершина
                    const int idx_C = idx_A + outer_grid_stride;
                    const int idx_D = idx_B + outer_grid_stride;

                    // Треугольник 1 (левый верхний)
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_X));
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_A));
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_C));

                    // Треугольник 2 (правый верхний)
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_X));
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_B));
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_A));

                    // Треугольник 3 (правый нижний)
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_X));
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_D));
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_B));

                    // Треугольник 4 (левый нижний)
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_X));
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_C));
                    worldTriangleIndices.push_back(static_cast<int>(vertexOffset + idx_D));
                }
            }
        }
    }
}

// ВНИМАНИЕ: Эта функция и связанный с ней член m_terrainTileIndices больше не используются.
// Их можно будет безопасно удалить после проверки корректной работы новой логики.
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
