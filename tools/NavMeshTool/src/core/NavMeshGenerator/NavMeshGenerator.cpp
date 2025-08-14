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
#include <filesystem>  // Для std::filesystem::create_directories
#include <QDir>        // Для альтернативного способа создания директорий через Qt

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

bool NavMeshGenerator::loadMapData(const std::string& mapName, uint32_t mapId,
                                   const std::vector<std::pair<int, int>>& adtCoords)
{
    Q_UNUSED(adtCoords);     // Пока не используем выборочную загрузку ADT
    m_currentMapId = mapId;  // Сохраняем ID карты для использования в других методах

    qCInfo(logNavMeshGenerator) << "Loading map data for map:" << QString::fromStdString(mapName)
                                << "with ID:" << mapId;

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

        // Передаем данные в обработчик, БЕЗ mapName
        // ПЕРЕВОРАЧИВАЕМ КООРДИНАТЫ!
        // Файловая система WoW (ADT_X_Y) и мировая система координат (World X, Y) инвертированы.
        // Файловый X (adtEntry.x) на самом деле соответствует мировому Y.
        // Файловый Y (adtEntry.y) на самом деле соответствует мировому X.
        // Поэтому мы передаем их в processAdtChunk в "перевернутом" виде.

        processAdtChunk(*adtDataOpt, adtEntry.x, adtEntry.y);
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

void NavMeshGenerator::processAdtChunk(const NavMeshTool::ADT::ADTData& adtData, int col, int row)
{
    // --- ЭТАП 1: СБОР ГЕОМЕТРИИ В КООРДИНАТАХ WoW ---

    std::vector<float> wowVertices;  // Вершины в системе WoW
    std::vector<int> wowIndices;     // Индексы для них

    // Наполняем векторы данными из ADT, WMO, M2.
    // Все эти process'ы должны возвращать геометрию в "перевернутой" системе WoW.
    m_terrainProcessor.process(adtData, row, col, wowVertices, wowIndices);
    m_wmoProcessor.process(adtData, m_processedWmoIds, wowVertices, wowIndices);
    m_m2Processor.process(adtData, m_processedM2Ids, wowVertices, wowIndices);

    if (wowVertices.empty() || wowIndices.empty())
    {
        qCDebug(logNavMeshGenerator) << "ADT at" << row << col << "has no geometry, skipping.";
        return;
    }

    // --- ЭТАП 2: СОХРАНЕНИЕ ОТЛАДОЧНОГО .OBJ В КООРДИНАТАХ WoW ---
    // СОХРАНЯЕМ ROW_COL - ПОТОМУ ЧТО В WoW СИСТЕМЕ ТАЙЛЫ ПЕРЕВЕРНУТЫ - ХЗ ПОЧЕМУ
    // НЕ УДАЛЯЙ ЭТОТ КОММЕНТАРИЙ ЧТОБЫ НЕ ЗАБЫТЬ!!!  если у нас было 43_12 то в игре это будет 12_43!
    const std::string outputDir = "output/" + std::to_string(m_currentMapId);
    QDir().mkpath(QString::fromStdString(outputDir));
    const std::string baseFilename = std::to_string(row) + "_" + std::to_string(col);
    const std::string wowObjFilename = outputDir + "/" + baseFilename + "_wow.obj";

    // Вызываем твой saveToObj с "чистыми" WoW-вершинами.
    if (saveToObj(wowObjFilename, wowVertices, wowIndices))
    {
        qCInfo(logNavMeshGenerator) << "Successfully saved WoW geometry to" << QString::fromStdString(wowObjFilename);
    }

    // --- ЭТАП 3: ПРЕОБРАЗОВАНИЕ В СИСТЕМУ RECAST ---

    std::vector<float> recastVertices = wowVertices;  // Создаем копию

    // Применяем нашу финальную, правильную формулу: (x, y, z) -> (-y, z, x)
    for (size_t i = 0; i < recastVertices.size(); i += 3)
    {
        const float x_wow = wowVertices[i];
        const float y_wow = wowVertices[i + 1];
        const float z_wow = wowVertices[i + 2];

        recastVertices[i] = -y_wow;     // Recast X <- WoW -Y
        recastVertices[i + 1] = z_wow;  // Recast Y <- WoW  Z
        recastVertices[i + 2] = x_wow;  // Recast Z <- WoW  X
    }

    // --- ЭТАП 4: СБОРКА И СОХРАНЕНИЕ NAVMESH ---

    const std::string navmeshFilename = outputDir + "/" + baseFilename + ".navmesh";
    const std::string navmeshObjFilename = outputDir + "/" + baseFilename + "_recast.obj";

    // Передаем в builder уже преобразованные вершины
    if (buildAndSaveNavMesh(navmeshFilename, navmeshObjFilename, recastVertices, wowIndices, col, row))
    {
        qCInfo(logNavMeshGenerator) << "Successfully processed ADT chunk for" << QString::fromStdString(baseFilename);
    }
    else
    {
        qCWarning(logNavMeshGenerator) << "Failed to build NavMesh for" << QString::fromStdString(baseFilename);
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

bool NavMeshGenerator::saveNavMeshToObj(const std::string& filepath, const rcPolyMesh* polyMesh) const
{
    if (!polyMesh)
    {
        return false;
    }

    std::ofstream objFile(filepath);
    if (!objFile.is_open())
    {
        qWarning(logNavMeshGenerator) << "Cannot open file for writing:" << QString::fromStdString(filepath);
        return false;
    }

    objFile << std::fixed << std::setprecision(6);

    // 1. Записываем вершины
    // Вершины в rcPolyMesh хранятся как unsigned short, которые нужно умножить на cs и ch
    // и прибавить к bmin, чтобы получить мировые координаты.
    for (int i = 0; i < polyMesh->nverts; ++i)
    {
        const unsigned short* v = &polyMesh->verts[i * 3];
        const float x = polyMesh->bmin[0] + v[0] * polyMesh->cs;
        const float y = polyMesh->bmin[1] + v[1] * polyMesh->ch;
        const float z = polyMesh->bmin[2] + v[2] * polyMesh->cs;
        objFile << "v " << x << " " << y << " " << z << "\n";
    }

    // 2. Записываем грани (полигоны)
    // Индексы в .obj начинаются с 1
    for (int i = 0; i < polyMesh->npolys; ++i)
    {
        const unsigned short* p = &polyMesh->polys[i * 2 * polyMesh->nvp];
        objFile << "f";
        for (int j = 0; j < polyMesh->nvp; ++j)
        {
            if (p[j] == RC_MESH_NULL_IDX)
            {
                break;  // Конец полигона
            }
            objFile << " " << (p[j] + 1);
        }
        objFile << "\n";
    }

    objFile.close();
    return true;
}

bool NavMesh::NavMeshGenerator::buildAndSaveNavMesh(const std::string& navMeshFilePath,
                                                    const std::string& navMeshObjFilePath,
                                                    const std::vector<float>& vertices, const std::vector<int>& indices,
                                                    int tx, int ty)
{
    // 1. Проверяем, есть ли у нас геометрия для обработки.
    if (vertices.empty() || indices.empty())
    {
        qCritical(logNavMeshGenerator) << "Геометрия не загружена. Невозможно построить NavMesh.";
        return false;
    }

    // 2. Настраиваем конфигурацию Recast.
    rcConfig config;
    memset(&config, 0, sizeof(config));
    config.cs = 1.0f;
    config.ch = 0.20f;
    config.walkableSlopeAngle = 45.0f;
    config.walkableHeight = (int)ceilf(2.0f / config.ch);
    config.walkableClimb = (int)floorf(2.0f / config.ch);
    config.walkableRadius = (int)ceilf(0.5f / config.cs);
    config.maxEdgeLen = (int)(12.0f / config.cs);
    config.maxSimplificationError = 1.3f;
    config.minRegionArea = (int)rcSqr(20);
    config.mergeRegionArea = (int)rcSqr(40);
    config.maxVertsPerPoly = 6;
    config.detailSampleDist = 6.0f;
    config.detailSampleMaxError = 1.0f;

    // 3. Создаем строителя, ПЕРЕДАВАЯ ему конфигурацию.
    NavMesh::RecastBuilder builder(config);

    // 4. Вызываем построение NavMesh
    qInfo(logNavMeshGenerator) << "Начинается генерация NavMesh для" << navMeshFilePath.c_str();

    auto buildResultOpt = builder.build(vertices, indices, tx, ty);

    if (!buildResultOpt)
    {
        qCritical(logNavMeshGenerator) << "Ошибка генерации NavMesh для" << navMeshFilePath.c_str();
        return false;
    }

    auto& buildResult = *buildResultOpt;
    qInfo(logNavMeshGenerator) << "NavMesh успешно сгенерирован. Размер:" << buildResult.navmeshData.size() << "байт.";

    // 5. Сохраняем результат в .navmesh файл
    try
    {
        std::ofstream outFile(navMeshFilePath, std::ios::binary);
        if (!outFile)
        {
            qCritical(logNavMeshGenerator) << "Не удалось открыть файл для записи:" << navMeshFilePath.c_str();
            return false;
        }

        outFile.write(reinterpret_cast<const char*>(buildResult.navmeshData.data()), buildResult.navmeshData.size());
        qInfo(logNavMeshGenerator) << "NavMesh сохранен в" << navMeshFilePath.c_str();
    }
    catch (const std::exception& e)
    {
        qCritical(logNavMeshGenerator) << "Ошибка при записи в файл:" << e.what();
        return false;
    }

    // 6. Сохраняем отладочный .obj файл
    if (saveNavMeshToObj(navMeshObjFilePath, buildResult.polyMesh.get()))
    {
        qCInfo(logNavMeshGenerator) << "Successfully saved NavMesh debug geometry to"
                                    << QString::fromStdString(navMeshObjFilePath);
    }
    else
    {
        qCWarning(logNavMeshGenerator) << "Failed to save NavMesh debug geometry to"
                                       << QString::fromStdString(navMeshObjFilePath);
    }

    return true;
}

}  // namespace NavMesh
