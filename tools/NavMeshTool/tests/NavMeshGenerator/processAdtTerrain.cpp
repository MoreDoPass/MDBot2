#include "processAdtTerrain.h"
#include "core/MpqManager/MpqManager.h"
#include "core/WoWFiles/Parsers/ADT/ADTParser.h"
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>
#include <cmath>
#include <array>
#include <optional>
#include <filesystem>
#include <regex>

// Объявляем функцию, которую будем вызывать из tests/main.cpp

// --- Начало блока, скопированного из NavMeshGenerator для изоляции теста ---

namespace
{
// Константы для расчетов геометрии, как в NavMeshGenerator
constexpr float TILE_SIZE = 1600.0f / 3.0f;
constexpr float MCNK_SIZE_UNITS = TILE_SIZE / 16.0f;
constexpr float UNIT_SIZE = MCNK_SIZE_UNITS / 8.0f;
constexpr float MAP_CHUNK_SIZE = TILE_SIZE * 32.0f;
constexpr float PI = 3.1415926535f;

// Вспомогательная структура для 3D-вектора
struct Vec3
{
    float x, y, z;
};
}  // namespace

// Скопированная функция для генерации индексов тайла
void buildTerrainTileIndices(std::vector<int>& terrainTileIndices)
{
    terrainTileIndices.clear();
    terrainTileIndices.reserve(8 * 8 * 4 * 3);  // 64 квада * 4 треугольника/квад * 3 вершины/треугольник

    // Итерируемся по рядам (i) и колонкам (j) квадов
    for (int i = 0; i < 8; ++i)
    {
        for (int j = 0; j < 8; ++j)
        {
            // Количество вершин в данных одного столбца (кроме последнего)
            // 9 вершин внешней сетки + 8 вершин внутренней сетки
            const int outer_grid_stride = 17;

            // Вычисляем индексы 5 вершин, которые формируют один квад
            // с центральной вершиной 'X'. Индексы локальны для одного чанка (0-144).
            const int idx_A = (i * outer_grid_stride) + j;      // Верхняя левая
            const int idx_B = idx_A + 1;                        // Верхняя правая
            const int idx_X = (i * outer_grid_stride) + 9 + j;  // Центральная (из внутренней сетки)
            const int idx_C = idx_A + outer_grid_stride;        // Нижняя левая
            const int idx_D = idx_B + outer_grid_stride;        // Нижняя правая

            // Создаем 4 треугольника, которые "веером" расходятся от центральной точки X.
            // Порядок вершин важен для правильного отображения лицевой стороны полигона.

            // Треугольник 1 (левый)
            terrainTileIndices.push_back(idx_X);
            terrainTileIndices.push_back(idx_A);
            terrainTileIndices.push_back(idx_C);

            // Треугольник 2 (верхний)
            terrainTileIndices.push_back(idx_X);
            terrainTileIndices.push_back(idx_B);
            terrainTileIndices.push_back(idx_A);

            // Треугольник 3 (правый)
            terrainTileIndices.push_back(idx_X);
            terrainTileIndices.push_back(idx_D);
            terrainTileIndices.push_back(idx_B);

            // Треугольник 4 (нижний)
            terrainTileIndices.push_back(idx_X);
            terrainTileIndices.push_back(idx_C);
            terrainTileIndices.push_back(idx_D);
        }
    }
}

// Тестовая версия processAdtTerrain.
// ПЕРЕПИСАНА С НУЛЯ для полного соответствия testik_latest.py
void processSingleAdtTerrain(const NavMeshTool::ADT::ADTData& adtData, int row, int col,
                             std::vector<float>& worldVertices, std::vector<int>& worldTriangleIndices,
                             const std::vector<int>& terrainTileIndices)
{
    for (const auto& mcnk : adtData.mcnkChunks)
    {
        if (mcnk.mcvtData.heights.empty()) continue;

        const size_t vertexOffset = worldVertices.size() / 3;

        // --- ТОЧНАЯ КОПИЯ ЛОГИКИ ИЗ PYTHON ---

        // 1. Вычисляем глобальные индексы pos_x и pos_y (как в ChunkCalculations.__init__)
        const int pos_x = (col * 16) + mcnk.header.indexX;
        const int pos_y = (row * 16) + mcnk.header.indexY;
        const int neighbor_chunk_index_x = pos_x + 1;
        const int neighbor_chunk_index_y = pos_y + 1;

        // 2. Вычисляем и кэшируем сетку (как в _calculate_world_coords_and_cache_grid)
        std::array<float, 9> VertexYCoordsCache_South;  // Соответствует VertexYCoordsCache в Python
        std::array<float, 9> VertexXCoordsCache_West;   // Соответствует VertexXCoordsCache в Python

        const float final_world_Y = MAP_CHUNK_SIZE - (static_cast<float>(pos_x) * MCNK_SIZE_UNITS);
        const float final_world_X = MAP_CHUNK_SIZE - (static_cast<float>(pos_y) * MCNK_SIZE_UNITS);

        VertexYCoordsCache_South[0] = final_world_Y;
        VertexXCoordsCache_West[0] = final_world_X;

        const float step = MCNK_SIZE_UNITS / 8.0f;
        for (int i = 1; i < 8; ++i)  // Цикл до 7, как в Python
        {
            VertexYCoordsCache_South[i] = final_world_Y - (step * i);
            VertexXCoordsCache_West[i] = final_world_X - (step * i);
        }

        // КРИТИЧЕСКИЙ МОМЕНТ: Вычисляем координаты для "шва" отдельно, используя индексы соседей.
        // Python: self.VertexYCoordsCache[8] = ZERO_POINT - (self.neighbor_chunk_index_x * CHUNK_SIZE)
        // Python: self.VertexXCoordsCache[8] = ZERO_POINT - (self.neighbor_chunk_index_y * CHUNK_SIZE)
        VertexYCoordsCache_South[8] = MAP_CHUNK_SIZE - (static_cast<float>(neighbor_chunk_index_x) * MCNK_SIZE_UNITS);
        VertexXCoordsCache_West[8] = MAP_CHUNK_SIZE - (static_cast<float>(neighbor_chunk_index_y) * MCNK_SIZE_UNITS);

        // 3. Строим вершины (как в build_vertices из Python)
        // Ключевое исправление: порядок добавления вершин должен быть чередующимся,
        // 9 внешних + 8 внутренних на каждый столбец, а не все внешние и потом все внутренние.
        const float world_z_base = mcnk.header.ypos;
        size_t mcvt_ptr = 0;

        for (int j = 0; j < 9; ++j)  // j - итератор по столбцам (ось X)
        {
            // 3.1. Обработка 9 вершин ВНЕШНЕЙ сетки для текущего столбца
            for (int i = 0; i < 9; ++i)  // i - итератор по рядам (ось Y)
            {
                const float world_x = VertexXCoordsCache_West[j];
                const float world_y = VertexYCoordsCache_South[i];
                const float world_z = world_z_base + mcnk.mcvtData.heights[mcvt_ptr + i];

                worldVertices.push_back(world_x);
                worldVertices.push_back(world_y);
                worldVertices.push_back(world_z);
            }
            mcvt_ptr += 9;

            // 3.2. Обработка 8 вершин ВНУТРЕННЕЙ сетки (только для первых 8 столбцов)
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

        // 4. Добавляем индексы (эта часть теперь будет работать правильно,
        // так как структура вершин в буфере соответствует ожиданиям)
        for (int index : terrainTileIndices)
        {
            worldTriangleIndices.push_back(static_cast<int>(vertexOffset + index));
        }
    }
}

// Скопированная функция для сохранения в .obj
bool saveToObj(const std::string& filepath, const std::vector<float>& vertices, const std::vector<int>& indices)
{
    std::ofstream objFile(filepath);
    if (!objFile.is_open())
    {
        std::cerr << "Cannot open file for writing: " << filepath << std::endl;
        return false;
    }

    objFile << std::fixed << std::setprecision(6);

    for (size_t i = 0; i < vertices.size(); i += 3)
    {
        objFile << "v " << vertices[i] << " " << vertices[i + 1] << " " << vertices[i + 2] << "\n";
    }

    for (size_t i = 0; i < indices.size(); i += 3)
    {
        objFile << "f " << (indices[i] + 1) << " " << (indices[i + 1] + 1) << " " << (indices[i + 2] + 1) << "\n";
    }

    objFile.close();
    return true;
}

// --- Конец блока, скопированного из NavMeshGenerator ---

int runFullTerrainGeneration()
{
    std::cout << "--- Full Terrain Generation Test from ADT files ---" << std::endl;

    const std::string adt_directory_path = "Data";

    if (!std::filesystem::exists(adt_directory_path))
    {
        std::cerr << "FATAL: ADT data directory not found at: " << adt_directory_path << std::endl;
        return 1;
    }

    // --- Глобальные контейнеры для всей геометрии мира ---
    std::vector<float> worldVertices;
    std::vector<int> worldTriangleIndices;

    // --- Предварительно создаем шаблон индексов для одного чанка, он всегда одинаковый ---
    std::vector<int> terrainTileIndices;
    buildTerrainTileIndices(terrainTileIndices);

    // --- Регулярное выражение для извлечения координат из имени файла (например, "MapName_col_row.adt") ---
    const std::regex adt_name_regex(R"(_(\d+)_(\d+)\.adt$)", std::regex_constants::icase);

    std::cout << "Scanning directory: " << adt_directory_path << " for .adt files..." << std::endl;

    for (const auto& entry : std::filesystem::directory_iterator(adt_directory_path))
    {
        if (!entry.is_regular_file() || entry.path().extension() != ".adt")
        {
            continue;
        }

        const std::string adt_path = entry.path().string();
        std::smatch match;

        // 1. Извлекаем координаты из имени файла
        if (!std::regex_search(adt_path, match, adt_name_regex) || match.size() != 3)
        {
            std::cout << "WARNING: Could not parse coordinates from filename: " << adt_path << ". Skipping."
                      << std::endl;
            continue;
        }

        const int col = std::stoi(match[1].str());
        const int row = std::stoi(match[2].str());

        std::cout << "--- Processing: " << adt_path << " (Col: " << col << ", Row: " << row << ") ---" << std::endl;

        // 2. Читаем файл с диска
        std::ifstream file(adt_path, std::ios::binary | std::ios::ate);
        if (!file)
        {
            std::cerr << "ERROR: Failed to open file: " << adt_path << std::endl;
            continue;
        }
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<unsigned char> adtBuffer(size);
        if (!file.read(reinterpret_cast<char*>(adtBuffer.data()), size))
        {
            std::cerr << "ERROR: Failed to read file content: " << adt_path << std::endl;
            continue;
        }

        // 3. Запускаем парсер
        NavMeshTool::ADT::Parser adtParser;
        auto adtDataOpt = adtParser.parse(adtBuffer, adt_path);

        if (!adtDataOpt)
        {
            std::cerr << "ERROR: ADT Parser failed for file: " << adt_path << ". Skipping." << std::endl;
            continue;
        }

        // 4. Обрабатываем данные и добавляем геометрию в общие векторы
        processSingleAdtTerrain(*adtDataOpt, row, col, worldVertices, worldTriangleIndices, terrainTileIndices);
    }

    if (worldVertices.empty())
    {
        std::cerr << "--- TEST FAILED: No vertices were generated from any ADT files. ---" << std::endl;
        return 1;
    }

    std::cout << "\n--- All ADT files processed. ---" << std::endl;
    std::cout << "Total vertices generated: " << worldVertices.size() / 3 << std::endl;
    std::cout << "Total indices generated: " << worldTriangleIndices.size() << std::endl;

    // 5. Сохраняем итоговую сетку в файл
    const std::string output_path = "terrain_mesh.obj";
    std::cout << "Saving final mesh to " << output_path << "..." << std::endl;
    if (saveToObj(output_path, worldVertices, worldTriangleIndices))
    {
        std::cout << "--- TEST SUCCEEDED: Successfully saved the combined terrain mesh. ---" << std::endl;
    }
    else
    {
        std::cerr << "--- TEST FAILED: Could not save the OBJ file. ---" << std::endl;
        return 1;
    }

    return 0;
}
