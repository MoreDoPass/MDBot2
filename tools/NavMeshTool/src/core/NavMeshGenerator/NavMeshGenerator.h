#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <QLoggingCategory>
#include <map>
#include <unordered_set>  // Подключаем для std::unordered_set

#include "core/WoWFiles/Parsers/WDT/WDTParser.h"
#include "core/WoWFiles/Parsers/ADT/ADTParser.h"
#include "core/WoWFiles/Parsers/M2/M2Parser.h"
#include "Processors/TerrainProcessor.h"  // Включаем новый обработчик
#include "Processors/WMOProcessor.h"      // Включаем новый обработчик WMO
#include "Processors/M2Processor.h"       // Включаем M2 обработчик

// Прямое объявление (Forward declaration) MpqManager, чтобы не подключать его заголовок сюда
// Это уменьшает связанность и время компиляции.
// Предполагается, что MpqManager находится в пространстве имен core (если это так)
// или глобальном пространстве имен. Если он в другом namespace, нужно указать.
class MpqManager;  // Если MpqManager в глобальном namespace

Q_DECLARE_LOGGING_CATEGORY(logNavMeshGenerator)  // Объявление категории логирования

namespace NavMesh
{  // Обернем все связанное с NavMesh в свое пространство имен

/**
 * @brief Основной класс для генерации навигационной сетки (NavMesh).
 * Отвечает за загрузку данных карты, извлечение геометрии,
 * ее трансформацию и последующую передачу в алгоритмы построения NavMesh.
 */
class NavMeshGenerator
{
   public:
    /**
     * @brief Конструктор.
     * @param mpqManager Ссылка на инициализированный MpqManager для доступа к файлам игры.
     */
    explicit NavMeshGenerator(MpqManager& mpqManager);

    /**
     * @brief Загружает данные карты и обрабатывает геометрию.
     * @param mapName Название карты (например, "Azeroth") или ID карты.
     *                Используется для формирования путей к файлам WDT, ADT и т.д.
     * @param adtCoords Опциональный список координат ADT (пары X,Y) для обработки.
     *                  Если пуст, могут обрабатываться все ADT карты (позже).
     * @return true, если данные успешно загружены и обработаны, иначе false.
     */
    bool loadMapData(const std::string& mapName, const std::vector<std::pair<int, int>>& adtCoords = {});

    /**
     * @brief Возвращает ссылку на массив собранных вершин.
     * Вершины хранятся как последовательность float (x1, y1, z1, x2, y2, z2, ...).
     * @return Константная ссылка на вектор вершин.
     */
    const std::vector<float>& getVertices() const;

    /**
     * @brief Возвращает ссылку на массив индексов треугольников.
     * Каждый треугольник представлен тремя индексами (i1, i2, i3, i4, i5, i6, ...).
     * Индексы указывают на начало группы из трех float в массиве, возвращаемом getVertices().
     * т.е. m_worldVertices[i1*3], m_worldVertices[i1*3+1], m_worldVertices[i1*3+2] это первая вершина
     * ПРАВИЛЬНЕЕ: Индексы указывают на порядковый номер вершины, а не на смещение в float массиве.
     * @return Константная ссылка на вектор индексов.
     */
    const std::vector<int>& getTriangleIndices() const;

    /**
     * @brief Сохраняет собранную геометрию в файл формата .obj.
     * @param filepath Путь к файлу для сохранения.
     * @return true, если сохранение прошло успешно, иначе false.
     */
    bool saveToObj(const std::string& filepath) const;

   private:
    MpqManager& m_mpqManager;                         // Ссылка на MPQ менеджер
    std::map<uint32_t, std::string> m_mapDbcEntries;  // Хранилище для данных из Map.dbc (ID -> DirectoryName)

    NavMeshTool::WDT::Parser m_wdtParser;  // Экземпляр парсера WDT
    NavMeshTool::ADT::Parser m_adtParser;  // Экземпляр парсера ADT
    // m_m2Parser теперь будет внутри M2Processor
    NavMesh::Processors::TerrainProcessor m_terrainProcessor;  // Обработчик ландшафта
    NavMesh::Processors::WmoProcessor m_wmoProcessor;          // Обработчик WMO
    NavMesh::Processors::M2Processor m_m2Processor;            // <--- Добавили

    NavMeshTool::WDT::WDTData m_currentWdtData;  // Данные, извлеченные из текущего WDT файла

    // Собранная геометрия мира
    // Вершины хранятся как набор координат: [x1, y1, z1, x2, y2, z2, ...]
    std::vector<float> m_worldVertices;
    // Индексы треугольников: каждый int - это индекс вершины в m_worldVertices.
    // [idx_v1_t1, idx_v2_t1, idx_v3_t1, idx_v1_t2, idx_v2_t2, idx_v3_t2, ...]
    std::vector<int> m_worldTriangleIndices;

    // Контейнеры для отслеживания уникальных ID обработанных объектов
    std::unordered_set<uint32_t> m_processedWmoIds;
    std::unordered_set<uint32_t> m_processedM2Ids;  // <--- Добавили

    /**
     * @brief Парсит данные файла Map.dbc.
     * @param buffer Буфер с данными файла Map.dbc.
     */
    void parseMapDbc(const std::vector<unsigned char>& buffer);

    void processAdtChunk(const NavMeshTool::ADT::ADTData& adtData, int row, int col);

    // Здесь будут приватные методы для парсинга WDT, ADT, WMO, M2,
    // трансформации координат и т.д.
    // void processWdt(const std::string& mapName);
    // void processAdt(int x, int y, const std::string& continentName);
    // void processWmo(...);
    // void processM2(...);
};

}  // namespace NavMesh
