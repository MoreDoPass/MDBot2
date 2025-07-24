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
#include "Builders/RecastBuilder.h"

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
    bool loadMapData(const std::string& mapName, uint32_t mapId, const std::vector<std::pair<int, int>>& adtCoords);

    /**
     * @brief Сохраняет собранную геометрию в файл формата .obj.
     * @param filepath Путь к файлу для сохранения.
     * @param vertices Вектор вершин для сохранения.
     * @param indices Вектор индексов для сохранения.
     * @return true, если сохранение прошло успешно, иначе false.
     */
    bool saveToObj(const std::string& filepath, const std::vector<float>& vertices,
                   const std::vector<int>& indices) const;

    /**
     * @brief Строит и сохраняет навигационную сетку (NavMesh).
     *
     * Этот метод использует переданную геометрию (вершины и индексы)
     * для построения NavMesh с помощью RecastBuilder. Результат сохраняется
     * в двоичный файл, совместимый с Detour.
     *
     * @param filepath Путь к файлу для сохранения NavMesh (например, "map.mmap").
     * @param vertices Вектор вершин для построения сетки.
     * @param indices Вектор индексов для построения сетки.
     * @return true, если построение и сохранение прошли успешно, иначе false.
     */
    bool buildAndSaveNavMesh(const std::string& navMeshFilePath, const std::string& navMeshObjFilePath,
                             const std::vector<float>& vertices, const std::vector<int>& indices);
    bool saveNavMeshToObj(const std::string& filepath, const rcPolyMesh* polyMesh) const;

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

    // Собранная геометрия мира больше не хранится на уровне класса.
    // Она будет создаваться, обрабатываться и уничтожаться для каждого ADT отдельно.

    // Контейнеры для отслеживания уникальных ID обработанных объектов
    std::unordered_set<uint32_t> m_processedWmoIds;
    std::unordered_set<uint32_t> m_processedM2Ids;  // <--- Добавили

    uint32_t m_currentMapId = 0;  ///< ID текущей обрабатываемой карты

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
