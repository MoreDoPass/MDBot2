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
    m_worldVertices.clear();
    m_worldTriangleIndices.clear();
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
        processAdtChunk(*adtDataOpt, adtEntry.y, adtEntry.x);
    }

    /*
    // 6. Обработка глобального WMO (если есть)
    if (!m_currentWdtData.modfEntries.empty() && !m_currentWdtData.mwmoFilenames.empty())
    {
        qCInfo(logNavMeshGenerator) << "Processing global WMO...";

        // Предполагаем, что для карты может быть только один глобальный WMO.
        const auto& globalWmoDef = m_currentWdtData.modfEntries[0];

        // ВАЖНО: globalWmoDef.nameId - это смещение в байтах в блоке MWMO, а не индекс.
        // WDT парсер (пока) не преобразует его в индекс.
        // Поскольку у нас есть только список имен, и мы не храним сырой блок MWMO,
        // мы делаем рискованное предположение, что nameId 0 соответствует первому файлу.
        // Это сработает, только если в WDT есть ровно один MODF и один MWMO файл.
        // TODO: Улучшить WDT парсер, чтобы он правильно разрешал nameId в индекс.
        if (globalWmoDef.nameId != 0)
        {
            qWarning(logNavMeshGenerator)
                << "Global WMO nameId is not 0, which is unhandled. Assuming index 0. This may be incorrect.";
        }

        // Мы вынуждены предполагать, что нужный нам файл находится под индексом 0.
        const std::string& wmoPath = m_currentWdtData.mwmoFilenames[0];

        std::vector<unsigned char> wmoBuffer;
        if (!m_mpqManager.readFile(wmoPath, wmoBuffer))
        {
            qWarning(logNavMeshGenerator) << "Could not read global WMO file:" << QString::fromStdString(wmoPath);
        }
        else
        {
            auto fileProvider = [this,
                                 &wmoPath](const std::string& filePath) -> std::optional<std::vector<unsigned char>>
            {
                std::string fullPath = filePath;
                if (filePath.find('\\') == std::string::npos && filePath.find('/') == std::string::npos)
                {
                    std::string wmoDir;
                    const auto last_slash = wmoPath.find_last_of("/\\");
                    if (std::string::npos != last_slash)
                    {
                        wmoDir = wmoPath.substr(0, last_slash + 1);
                    }
                    fullPath = wmoDir + filePath;
                }

                std::string pathForMpq = fullPath;
                const auto extPos = pathForMpq.rfind('.');
                if (extPos != std::string::npos)
                {
                    if (_stricmp(pathForMpq.c_str() + extPos, ".MDX") == 0 ||
                        _stricmp(pathForMpq.c_str() + extPos, ".MDL") == 0)
                    {
                        pathForMpq.replace(extPos, 4, ".M2");
                    }
                }

                std::vector<unsigned char> buffer;
                if (m_mpqManager.readFile(pathForMpq, buffer))
                {
                    return buffer;
                }
                if (pathForMpq != fullPath)
                {
                    if (m_mpqManager.readFile(fullPath, buffer))
                    {
                        return buffer;
                    }
                }
                return std::nullopt;
            };

            auto wmoDataOpt = m_wmoParser.parse(wmoPath, wmoBuffer, fileProvider);
            if (!wmoDataOpt)
            {
                qWarning(logNavMeshGenerator) << "Could not parse global WMO file:" << QString::fromStdString(wmoPath);
            }
            else
            {
                const auto& wmoData = *wmoDataOpt;
                const size_t vertexOffset = m_worldVertices.size() / 3;

                const float posX = MAP_CHUNK_SIZE - globalWmoDef.position[1];  // Y
                const float posY = MAP_CHUNK_SIZE - globalWmoDef.position[0];  // X
                const float posZ = globalWmoDef.position[2];                   // Z

                // WDT orientation: {rot_x, rot_y, rot_z}
                // ADT rotation: {rot_y, rot_z, rot_x}
                // Мы должны использовать ту же трансформацию, что и для ADT WMOs.
                // ADT rotY -> WDT oriY, ADT rotZ -> WDT oriZ, ADT rotX -> WDT oriX
                const float rotX_rad = globalWmoDef.orientation[1] * (PI / 180.0f);
                const float rotY_rad = globalWmoDef.orientation[2] * (PI / 180.0f);
                const float rotZ_rad = globalWmoDef.orientation[0] * (PI / 180.0f);

                for (const auto& wmoVert : wmoData.vertices)
                {
                    Vec3 vert = {-wmoVert.y, -wmoVert.x, wmoVert.z};

                    float newX = vert.x * cos(rotZ_rad) - vert.y * sin(rotZ_rad);
                    float newY = vert.x * sin(rotZ_rad) + vert.y * cos(rotZ_rad);
                    vert.x = newX;
                    vert.y = newY;

                    newX = vert.x * cos(rotY_rad) + vert.z * sin(rotY_rad);
                    float newZ = -vert.x * sin(rotY_rad) + vert.z * cos(rotY_rad);
                    vert.x = newX;
                    vert.z = newZ;

                    newY = vert.y * cos(rotX_rad) - vert.z * sin(rotX_rad);
                    newZ = vert.y * sin(rotX_rad) + vert.z * cos(rotX_rad);
                    vert.y = newY;
                    vert.z = newZ;

                    m_worldVertices.push_back(vert.x + posX);
                    m_worldVertices.push_back(vert.y + posY);
                    m_worldVertices.push_back(vert.z + posZ);
                }

                for (int index : wmoData.indices)
                {
                    m_worldTriangleIndices.push_back(static_cast<int>(vertexOffset + index));
                }

                qCInfo(logNavMeshGenerator) << "Successfully processed global WMO:" << QString::fromStdString(wmoPath);
            }
        }
    }
    */

    qInfo(logNavMeshGenerator) << "Finished processing all ADTs for map" << QString::fromStdString(mapName);

    // Временный экспорт в .obj для отладки
    if (saveToObj(mapName + ".obj"))
    {
        qInfo(logNavMeshGenerator) << "Successfully saved geometry to" << QString::fromStdString(mapName + ".obj");
    }
    else
    {
        qWarning(logNavMeshGenerator) << "Failed to save geometry to" << QString::fromStdString(mapName + ".obj");
    }

    return true;
}

const std::vector<float>& NavMeshGenerator::getVertices() const
{
    return m_worldVertices;
}

const std::vector<int>& NavMeshGenerator::getTriangleIndices() const
{
    return m_worldTriangleIndices;
}

// Приватный метод для парсинга Map.dbc
void NavMeshGenerator::parseMapDbc(const std::vector<unsigned char>& buffer)
{
    Q_UNUSED(buffer);
    // TODO: Implement Map.dbc parsing if needed for map names by ID
}

void NavMeshGenerator::processAdtChunk(const NavMeshTool::ADT::ADTData& adtData, int row, int col)
{
    // Этот метод теперь является "оркестратором" для обработки одного ADT.
    // Он последовательно вызывает обработчики для каждого типа геометрии.
    m_terrainProcessor.process(adtData, row, col, m_worldVertices, m_worldTriangleIndices);
    m_wmoProcessor.process(adtData, m_processedWmoIds, m_worldVertices, m_worldTriangleIndices);
    m_m2Processor.process(adtData, m_processedM2Ids, m_worldVertices, m_worldTriangleIndices);
}

bool NavMeshGenerator::saveToObj(const std::string& filepath) const
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
    for (size_t i = 0; i < m_worldVertices.size(); i += 3)
    {
        objFile << "v " << m_worldVertices[i] << " " << m_worldVertices[i + 1] << " " << m_worldVertices[i + 2] << "\n";
    }

    // Записываем все грани (треугольники)
    // В .obj индексация начинается с 1
    for (size_t i = 0; i < m_worldTriangleIndices.size(); i += 3)
    {
        objFile << "f " << (m_worldTriangleIndices[i] + 1) << " " << (m_worldTriangleIndices[i + 1] + 1) << " "
                << (m_worldTriangleIndices[i + 2] + 1) << "\n";
    }

    objFile.close();
    return true;
}

}  // namespace NavMesh
