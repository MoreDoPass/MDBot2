#include "NavMeshGenerator.h"
#include "core/MpqManager/MpqManager.h"  // Включаем для доступа к методам MpqManager
#include "core/WoWFiles/Parsers/M2/M2Parser.h"
#include <QLoggingCategory>
#include <QDebug>
#include <cstring>  // Для memcpy или безопасного reinterpret_cast
#include <string>
#include <fstream>
#include <iomanip>
#include <cmath>  // Для sin, cos
#include <array>

// Пока что MpqManager.h не нужен здесь, так как мы работаем только со ссылкой,
// а все вызовы будут через m_mpqManager, тип которой уже известен из NavMeshGenerator.h
// #include "../../MpqManager/MpqManager.h" // Если бы мы создавали MpqManager здесь или использовали его конкретные
// типы

// #include <iostream>  // Заменяем на Qt логгер

// Константы для расчетов геометрии, согласно документации ADT
namespace
{
constexpr float TILE_SIZE = 1600.0f / 3.0f;          // ~533.33333 ярдов
constexpr float MAP_CHUNK_SIZE = TILE_SIZE * 32.0f;  // 17066.666
constexpr float PI = 3.1415926535f;

// Вспомогательная структура для 3D-вектора, чтобы сделать код чище
struct Vec3
{
    float x, y, z;
};
}  // namespace

Q_LOGGING_CATEGORY(logNavMeshGenerator, "navmesh.generator")  // Определение категории логирования

namespace NavMesh
{

NavMeshGenerator::NavMeshGenerator(MpqManager& mpqManager)
    : m_mpqManager(mpqManager),
      m_terrainProcessor(),
      m_wmoProcessor(mpqManager),
      m_m2Processor(mpqManager)  // Инициализируем M2 процессор
{
    qCDebug(logNavMeshGenerator) << "NavMeshGenerator created.";
}

bool NavMeshGenerator::loadMapData(const std::string& mapName, const std::vector<std::pair<int, int>>& adtCoords)
{
    Q_UNUSED(adtCoords);  // Пока не используем выборочную загрузку ADT

    qCInfo(logNavMeshGenerator) << "Loading map data for map:" << QString::fromStdString(mapName);

    // Очищаем данные от предыдущих запусков (если есть)
    // m_worldVertices и m_worldTriangleIndices удалены
    m_processedWmoIds.clear();
    m_processedM2Ids.clear();  // Очищаем set для M2

    // 1. Загрузка и парсинг WDT
    std::string wdtPath = "World\\maps\\" + mapName + "\\" + mapName + ".wdt";
    std::vector<unsigned char> wdtBuffer;

    if (!m_mpqManager.readFile(wdtPath, wdtBuffer))
    {
        qCritical(logNavMeshGenerator) << "Failed to read WDT file:" << QString::fromStdString(wdtPath);
        return false;
    }

    auto wdtDataOpt = m_wdtParser.parse(wdtBuffer, mapName);
    if (!wdtDataOpt)
    {
        qCritical(logNavMeshGenerator) << "Failed to parse WDT file:" << QString::fromStdString(wdtPath);
        return false;
    }
    m_currentWdtData = *wdtDataOpt;
    qInfo(logNavMeshGenerator) << "Successfully parsed WDT for map" << QString::fromStdString(mapName);

    // 2. Основной цикл загрузки ADT
    for (const auto& adtEntry : m_currentWdtData.adtFilenames)
    {
        const std::string& adtFileName = adtEntry.filename;
        qDebug(logNavMeshGenerator) << "Processing ADT:" << QString::fromStdString(adtFileName) << "Coords:("
                                    << adtEntry.x << "," << adtEntry.y << ")";

        // Читаем файл ADT из MPQ
        std::vector<unsigned char> adtBuffer;
        if (!m_mpqManager.readFile(adtFileName, adtBuffer))
        {
            qWarning(logNavMeshGenerator) << "Could not read ADT file:" << QString::fromStdString(adtFileName);
            continue;  // Пропускаем этот ADT
        }

        // Парсим ADT, передавая имя файла
        auto adtDataOpt = m_adtParser.parse(adtBuffer, adtFileName);
        if (!adtDataOpt)
        {
            qWarning(logNavMeshGenerator) << "Could not parse ADT file:" << QString::fromStdString(adtFileName);
            continue;  // Пропускаем
        }

        // Передаем данные в обработчик
        processAdtChunk(mapName, *adtDataOpt, adtEntry.y, adtEntry.x);
    }

    qInfo(logNavMeshGenerator) << "Finished processing all ADTs for map" << QString::fromStdString(mapName);

    // Глобальный вызов saveToObj и buildAndSaveNavMesh убран отсюда

    return true;
}

// Методы getVertices и getTriangleIndices полностью удалены

// Приватный метод для парсинга Map.dbc
void NavMeshGenerator::parseMapDbc(const std::vector<unsigned char>& buffer)
{
    Q_UNUSED(buffer);
    // TODO: Implement Map.dbc parsing if needed for map names by ID
}

void NavMeshGenerator::processAdtChunk(const std::string& mapName, const NavMeshTool::ADT::ADTData& adtData, int row,
                                       int col)
{
    // Этот метод теперь является "фабрикой" для одного ADT-тайла.

    // 1. Создаем локальные контейнеры для геометрии этого чанка
    std::vector<float> adtVertices;
    std::vector<int> adtIndices;

    // 2. Последовательно вызываем обработчики, которые наполняют локальные контейнеры
    m_terrainProcessor.process(adtData, row, col, adtVertices, adtIndices);
    m_wmoProcessor.process(adtData, m_processedWmoIds, adtVertices, adtIndices);
    m_m2Processor.process(adtData, m_processedM2Ids, adtVertices, adtIndices);

    // 3. Преобразование системы координат для Recast (Y-вперед -> Y-вверх)
    // После того как вся геометрия для тайла собрана, мы должны поменять ее
    // систему координат, чтобы она соответствовала тому, что ожидает Recast.
    // Recast использует систему, где Y - это "верх". В наших данных Z - это "верх".
    // Преобразование: (x, y, z) -> (x, z, -y)
    for (size_t i = 0; i < adtVertices.size(); i += 3)
    {
        // adtVertices[i] (координата X) остается без изменений.
        const float y = adtVertices[i + 1];
        const float z = adtVertices[i + 2];
        adtVertices[i + 1] = z;   // Новая координата Y - это старая Z.
        adtVertices[i + 2] = -y;  // Новая координата Z - это инвертированная старая Y.
    }

    // Если после обработки геометрия пуста, нет смысла продолжать
    if (adtVertices.empty() || adtIndices.empty())
    {
        qCDebug(logNavMeshGenerator) << "ADT at" << row << col << "has no geometry, skipping.";
        return;
    }

    // 4. (Опционально) Сохраняем геометрию этого ADT в .obj для отладки
    std::string objFilename = mapName + "_" + std::to_string(col) + "_" + std::to_string(row) + ".obj";
    if (saveToObj(objFilename, adtVertices, adtIndices))
    {
        qCInfo(logNavMeshGenerator) << "Successfully saved ADT geometry to" << QString::fromStdString(objFilename);
    }
    else
    {
        qCWarning(logNavMeshGenerator) << "Failed to save ADT geometry to" << QString::fromStdString(objFilename);
    }

    // 5. Строим и сохраняем NavMesh для этого ADT
    std::string navmeshFilename = mapName + "_" + std::to_string(col) + "_" + std::to_string(row) + ".navmesh";
    if (buildAndSaveNavMesh(navmeshFilename, adtVertices, adtIndices))
    {
        qCInfo(logNavMeshGenerator) << "Successfully built and saved NavMesh to"
                                    << QString::fromStdString(navmeshFilename);
    }
    else
    {
        qCWarning(logNavMeshGenerator) << "Failed to build NavMesh for" << QString::fromStdString(navmeshFilename);
    }
}

bool NavMeshGenerator::saveToObj(const std::string& filepath, const std::vector<float>& vertices,
                                 const std::vector<int>& indices) const
{
    std::ofstream objFile(filepath);
    if (!objFile.is_open())
    {
        qWarning(logNavMeshGenerator) << "Cannot open file for writing:" << QString::fromStdString(filepath);
        return false;
    }

    // Устанавливаем высокую точность для float
    objFile << std::fixed << std::setprecision(6);

    // Записываем все вершины
    for (size_t i = 0; i < vertices.size(); i += 3)
    {
        objFile << "v " << vertices[i] << " " << vertices[i + 1] << " " << vertices[i + 2] << "\n";
    }

    // Записываем все грани (треугольники)
    // В .obj индексация начинается с 1
    for (size_t i = 0; i < indices.size(); i += 3)
    {
        objFile << "f " << (indices[i] + 1) << " " << (indices[i + 1] + 1) << " " << (indices[i + 2] + 1) << "\n";
    }

    objFile.close();
    return true;
}

bool NavMesh::NavMeshGenerator::buildAndSaveNavMesh(const std::string& filepath, const std::vector<float>& vertices,
                                                    const std::vector<int>& indices) const
{
    // 1. Проверяем, есть ли у нас геометрия для обработки.
    if (vertices.empty() || indices.empty())
    {
        qCritical(logNavMeshGenerator) << "Геометрия не загружена. Невозможно построить NavMesh.";
        return false;
    }

    // 2. Настраиваем конфигурацию Recast.
    // Это базовые параметры. В будущем их можно будет вынести в GUI
    // или загружать из файла конфигурации.
    rcConfig config;
    memset(&config, 0, sizeof(config));

    // РАДИКАЛЬНОЕ ИЗМЕНЕНИЕ: Увеличиваем размер вокселя для борьбы с экстремально "шумными" тайлами.
    // Это основной способ "загрубить" геометрию на самом раннем этапе.
    config.cs = 1.0f;  // Было 0.3
    config.ch = 1.0f;  // Было 0.2

    config.walkableSlopeAngle = 45.0f;
    config.walkableHeight = (int)ceilf(2.0f / config.ch);
    config.walkableClimb = (int)floorf(0.9f / config.ch);
    config.walkableRadius = (int)ceilf(0.5f / config.cs);
    config.maxEdgeLen = (int)(12.0f / config.cs);
    config.maxSimplificationError = 1.3f;

    // Оставляем увеличенные значения из прошлой попытки.
    config.minRegionArea = (int)rcSqr(20);
    config.mergeRegionArea = (int)rcSqr(40);

    config.maxVertsPerPoly = 6;
    config.detailSampleDist = 6.0f;
    config.detailSampleMaxError = 1.0f;

    // 3. Создаем строителя, ПЕРЕДАВАЯ ему конфигурацию.
    NavMesh::RecastBuilder builder(config);

    // 4. Вызываем построение NavMesh
    qInfo(logNavMeshGenerator) << "Начинается генерация NavMesh для" << filepath.c_str();

    // Передаем константные ссылки на наши векторы геометрии
    auto navMeshData = builder.build(vertices, indices);

    if (!navMeshData)
    {
        qCritical(logNavMeshGenerator) << "Ошибка генерации NavMesh для" << filepath.c_str();
        return false;
    }

    qInfo(logNavMeshGenerator) << "NavMesh успешно сгенерирован. Размер:" << navMeshData->size() << "байт.";

    // 5. Сохраняем результат в файл
    try
    {
        std::ofstream outFile(filepath, std::ios::binary);
        if (!outFile)
        {
            qCritical(logNavMeshGenerator) << "Не удалось открыть файл для записи:" << filepath.c_str();
            return false;
        }

        outFile.write(reinterpret_cast<const char*>(navMeshData->data()), navMeshData->size());
        qInfo(logNavMeshGenerator) << "NavMesh сохранен в" << filepath.c_str();
    }
    catch (const std::exception& e)
    {
        qCritical(logNavMeshGenerator) << "Ошибка при записи в файл:" << e.what();
        return false;
    }

    return true;
}

}  // namespace NavMesh
