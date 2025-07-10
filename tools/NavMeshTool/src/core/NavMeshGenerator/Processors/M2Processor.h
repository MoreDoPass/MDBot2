#pragma once

#include <vector>
#include <string>
#include <unordered_set>
#include "core/WoWFiles/Parsers/ADT/ADTParser.h"
#include "core/WoWFiles/Parsers/M2/M2Parser.h"

// Прямое объявление, чтобы не включать MpqManager.h
class MpqManager;

namespace NavMesh
{
namespace Processors
{

/**
 * @class M2Processor
 * @brief Отвечает за обработку геометрии M2 моделей (doodads) из ADT файлов.
 *
 * Этот класс инкапсулирует логику для чтения, парсинга и трансформации
 * M2 моделей, которые размещены на тайлах карты.
 * Отслеживает уникальные ID объектов, чтобы избежать многократной обработки.
 */
class M2Processor
{
   public:
    /**
     * @brief Конструктор.
     * @param mpqManager Ссылка на MPQ менеджер для доступа к файлам игры.
     */
    explicit M2Processor(MpqManager& mpqManager);

    /**
     * @brief Обрабатывает M2, определенные в одном ADT файле.
     *
     * @param adtData Распарсенные данные ADT.
     * @param processedIds Ссылка на set, содержащий uniqueId уже обработанных M2.
     * @param worldVertices Ссылка на вектор, в который будут добавлены вершины геометрии.
     * @param worldTriangleIndices Ссылка на вектор, в который будут добавлены индексы треугольников.
     */
    void process(const NavMeshTool::ADT::ADTData& adtData, std::unordered_set<uint32_t>& processedIds,
                 std::vector<float>& worldVertices, std::vector<int>& worldTriangleIndices);

   private:
    MpqManager& m_mpqManager;            ///< Ссылка на MPQ менеджер.
    NavMeshTool::M2::Parser m_m2Parser;  ///< Экземпляр парсера M2.
};

}  // namespace Processors
}  // namespace NavMesh
