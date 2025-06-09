#pragma once

#include <vector>
#include <string>
#include <cstdint>           // Для uint32_t или int в Triangle
#include <QLoggingCategory>  // Добавлено для логирования
#include <map>               // Добавлено для std::map

// Подключаем парсер WDT
#include "core/WoWFiles/Parsers/WDT/WDTParser.h"
#include "core/WoWFiles/Parsers/ADT/ADTParser.h"
#include "core/WoWFiles/Parsers/WMO/WMOParser.h"

// Прямое объявление (Forward declaration) MpqManager, чтобы не подключать его заголовок сюда
// Это уменьшает связанность и время компиляции.
// Предполагается, что MpqManager находится в пространстве имен core (если это так)
// или глобальном пространстве имен. Если он в другом namespace, нужно указать.
class MpqManager;  // Если MpqManager в глобальном namespace

Q_DECLARE_LOGGING_CATEGORY(logNavMeshGenerator)  // Объявление категории логирования

namespace NavMesh
{  // Обернем все связанное с NavMesh в свое пространство имен

/**
 * @brief Структура для представления 3D вершины.
 */
struct Vertex
{
    float x, y, z;
};

/**
 * @brief Структура для представления треугольника через индексы его вершин.
 * Индексы указывают на элементы в общем массиве вершин.
 */
struct Triangle
{
    // Используем int или uint32_t в зависимости от ожидаемого количества вершин.
    // int обычно достаточно для большинства практических случаев.
    int v1_idx;
    int v2_idx;
    int v3_idx;
};

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

    NavMeshTool::WDT::Parser m_wdtParser;        // Экземпляр парсера WDT
    NavMeshTool::ADT::Parser m_adtParser;        // Экземпляр парсера ADT
    NavMeshTool::WMO::Parser m_wmoParser;        // Экземпляр парсера WMO
    NavMeshTool::WDT::WDTData m_currentWdtData;  // Данные, извлеченные из текущего WDT файла

    // Собранная геометрия мира
    // Вершины хранятся как набор координат: [x1, y1, z1, x2, y2, z2, ...]
    std::vector<float> m_worldVertices;
    // Индексы треугольников: каждый int - это индекс вершины в m_worldVertices / 3.
    // [idx_v1_t1, idx_v2_t1, idx_v3_t1, idx_v1_t2, idx_v2_t2, idx_v3_t2, ...]
    std::vector<int> m_worldTriangleIndices;
    std::vector<int> m_terrainTileIndices;  // Пред-рассчитанные индексы для одного MCNK

    /**
     * @brief Парсит данные файла Map.dbc.
     * @param buffer Буфер с данными файла Map.dbc.
     */
    void parseMapDbc(const std::vector<unsigned char>& buffer);

    void processAdtChunk(const NavMeshTool::ADT::ADTData& adtData, int row, int col);

    // Приватные методы для обработки составных частей ADT
    void processAdtTerrain(const NavMeshTool::ADT::ADTData& adtData, int row, int col);
    void processAdtWmos(const NavMeshTool::ADT::ADTData& adtData);
    void processAdtM2s(const NavMeshTool::ADT::ADTData& adtData);

    void buildTerrainTileIndices();

    // Здесь будут приватные методы для парсинга WDT, ADT, WMO, M2,
    // трансформации координат и т.д.
    // void processWdt(const std::string& mapName);
    // void processAdt(int x, int y, const std::string& continentName);
    // void processWmo(...);
    // void processM2(...);
};

}  // namespace NavMesh
