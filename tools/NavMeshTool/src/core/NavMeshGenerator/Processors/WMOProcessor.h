#pragma once

#include <vector>
#include <string>
#include <unordered_set>
#include "core/WoWFiles/Parsers/ADT/ADTParser.h"
#include "core/WoWFiles/Parsers/WMO/WMOParser.h"

// Прямое объявление, чтобы не включать MpqManager.h
class MpqManager;

namespace NavMesh
{
namespace Processors
{

/**
 * @class WmoProcessor
 * @brief Отвечает за обработку геометрии WMO (World Map Objects) из ADT файлов.
 *
 * Этот класс инкапсулирует логику для чтения, парсинга и трансформации
 * WMO моделей, которые размещены на тайлах карты.
 * Ключевой особенностью является отслеживание уникальных ID объектов,
 * чтобы избежать многократной обработки одного и того же объекта (например,
 * большого WMO, который пересекает несколько тайлов).
 */
class WmoProcessor
{
   public:
    /**
     * @brief Конструктор.
     * @param mpqManager Ссылка на MPQ менеджер для доступа к файлам игры.
     */
    explicit WmoProcessor(MpqManager& mpqManager);

    /**
     * @brief Обрабатывает WMO, определенные в одном ADT файле.
     *
     * @param adtData Распарсенные данные ADT.
     * @param processedIds Ссылка на set, содержащий uniqueId уже обработанных WMO.
     *                     Метод будет использовать этот set для проверки и обновлять его.
     * @param worldVertices Ссылка на вектор, в который будут добавлены вершины геометрии.
     * @param worldTriangleIndices Ссылка на вектор, в который будут добавлены индексы треугольников.
     */
    void process(const NavMeshTool::ADT::ADTData& adtData, std::unordered_set<uint32_t>& processedIds,
                 std::vector<float>& worldVertices, std::vector<int>& worldTriangleIndices);

   private:
    MpqManager& m_mpqManager;              ///< Ссылка на MPQ менеджер.
    NavMeshTool::WMO::Parser m_wmoParser;  ///< Экземпляр парсера WMO.
};

}  // namespace Processors
}  // namespace NavMesh
