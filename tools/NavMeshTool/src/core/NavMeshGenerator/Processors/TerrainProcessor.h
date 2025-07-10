#pragma once

#include <vector>
#include "../../WoWFiles/Parsers/ADT/ADTParser.h"

namespace NavMesh
{
namespace Processors
{
/**
 * @class TerrainProcessor
 * @brief Отвечает за обработку геометрии ландшафта (terrain) из ADT файлов.
 *
 * Этот класс инкапсулирует логику для преобразования данных о высоте
 * ландшафта из MCNK чанков в треугольную сетку, готовую для использования
 * в генерации навигационной сетки.
 */
class TerrainProcessor
{
   public:
    /**
     * @brief Конструктор по умолчанию.
     */
    TerrainProcessor();

    /**
     * @brief Обрабатывает геометрию ландшафта из одного ADT файла.
     *
     * Метод проходит по всем MCNK чанкам в предоставленных данных ADT,
     * вычисляет мировые координаты вершин ландшафта и генерирует
     * треугольники, добавляя их в предоставленные векторы.
     *
     * @param adtData Распарсенные данные ADT, содержащие информацию о ландшафте.
     * @param row Индекс строки ADT на карте (используется для вычисления глобальных координат).
     * @param col Индекс колонки ADT на карте (используется для вычисления глобальных координат).
     * @param worldVertices Ссылка на вектор, в который будут добавлены вершины геометрии ландшафта.
     * @param worldTriangleIndices Ссылка на вектор, в который будут добавлены индексы треугольников.
     */
    void process(const NavMeshTool::ADT::ADTData& adtData, int row, int col, std::vector<float>& worldVertices,
                 std::vector<int>& worldTriangleIndices);

   private:
    /**
     * @brief Создает шаблон индексов для одного тайла ландшафта (MCNK чанка).
     *
     * Этот шаблон используется для всех MCNK чанков, так как их структура сетки одинакова.
     * Метод вызывается один раз при необходимости для кеширования индексов.
     */
    void buildTerrainTileIndices();

    /// @brief Кешированные индексы треугольников для одного MCNK чанка.
    std::vector<int> m_terrainTileIndices;
};

}  // namespace Processors
}  // namespace NavMesh
