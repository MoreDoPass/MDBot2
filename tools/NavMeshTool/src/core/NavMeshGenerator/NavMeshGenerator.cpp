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

// Пока что MpqManager.h не нужен здесь, так как мы работаем только со ссылкой,
// а все вызовы будут через m_mpqManager, тип которой уже известен из NavMeshGenerator.h
// #include "../../MpqManager/MpqManager.h" // Если бы мы создавали MpqManager здесь или использовали его конкретные
// типы

// #include <iostream>  // Заменяем на Qt логгер

// Константы для расчетов геометрии, согласно документации ADT
namespace
{
constexpr float TILE_SIZE = 1600.0f / 3.0f;           // ~533.33333 ярдов
constexpr float MCNK_SIZE_UNITS = TILE_SIZE / 16.0f;  // ~33.33333 ярдов
constexpr float UNIT_SIZE = MCNK_SIZE_UNITS / 8.0f;   // ~4.16666 ярдов
constexpr float MAP_CHUNK_SIZE = TILE_SIZE * 32.0f;   // 17066.666
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
    : m_mpqManager(mpqManager)  // Инициализация ссылки в списке инициализации конструктора
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
    processAdtTerrain(adtData, row, col);
    processAdtWmos(adtData);
    processAdtM2s(adtData);
}

void NavMeshGenerator::processAdtTerrain(const NavMeshTool::ADT::ADTData& adtData, int row, int col)
{
    Q_UNUSED(row);
    Q_UNUSED(col);

    // Если индексы для тайла еще не были сгенерированы, делаем это
    if (m_terrainTileIndices.empty())
    {
        buildTerrainTileIndices();
    }

    // Проходим по каждому из 256 чанков (16x16) в данном ADT
    for (const auto& mcnk : adtData.mcnkChunks)
    {
        // Проверяем, есть ли в этом чанке геометрия
        if (mcnk.header.flags & 0x40 ||
            mcnk.mcvtData.heights
                .empty())  // has_mccv, но в нашем случае это может означать, что нет вершин. Проверяем и сам массив.
            continue;

        // 1. Сохраняем текущее количество вершин. Это будет смещение для индексов этого чанка.
        const size_t vertexOffset = m_worldVertices.size() / 3;

        // 2. Рассчитываем мировые координаты.
        // Заголовок MCNK УЖЕ содержит готовые мировые координаты центра чанка.
        // Используем их напрямую, без каких-либо трансформаций.
        // Это ключевое исправление: мы больше не используем MAP_CHUNK_SIZE для ландшафта.
        const float centerX = mcnk.header.xpos;
        const float centerY = mcnk.header.zpos;  // В файле zpos - это мировая Y
        const float centerZ = mcnk.header.ypos;  // В файле ypos - это мировая Z (высота)

        // Координаты северо-восточного угла чанка.
        // В WoW +X = Юг, +Y = Запад. Поэтому северо-восток - это наименьшие X и Y.
        const float ne_corner_x = centerX - (MCNK_SIZE_UNITS / 2.0f);
        const float ne_corner_y = centerY - (MCNK_SIZE_UNITS / 2.0f);

        // Внешние вершины (9x9)
        for (int j = 0; j < 9; ++j)
        {
            for (int i = 0; i < 9; ++i)
            {
                const float height = mcnk.mcvtData.heights[j * 9 + i];
                float x = ne_corner_x + (i * UNIT_SIZE);
                float y = ne_corner_y + (j * UNIT_SIZE);
                float z = centerZ + height;
                // 1. Инверсия по X
                x = -x;
                // 2. Поворот на 270 градусов против часовой стрелки
                float angle_rad = 270.0f * (PI / 180.0f);
                float newX = x * cos(angle_rad) - y * sin(angle_rad);
                float newY = x * sin(angle_rad) + y * cos(angle_rad);
                m_worldVertices.push_back(newX);
                m_worldVertices.push_back(newY);
                m_worldVertices.push_back(z);
            }
        }
        // Внутренние вершины (8x8)
        for (int j = 0; j < 8; ++j)
        {
            for (int i = 0; i < 8; ++i)
            {
                const float height = mcnk.mcvtData.heights[81 + j * 8 + i];
                float x = ne_corner_x + (i * UNIT_SIZE) + (UNIT_SIZE / 2.0f);
                float y = ne_corner_y + (j * UNIT_SIZE) + (UNIT_SIZE / 2.0f);
                float z = centerZ + height;
                // 1. Инверсия по X
                x = -x;
                // 2. Поворот на 270 градусов против часовой стрелки
                float angle_rad = 270.0f * (PI / 180.0f);
                float newX = x * cos(angle_rad) - y * sin(angle_rad);
                float newY = x * sin(angle_rad) + y * cos(angle_rad);
                m_worldVertices.push_back(newX);
                m_worldVertices.push_back(newY);
                m_worldVertices.push_back(z);
            }
        }
        // 3. Добавляем пред-рассчитанные индексы треугольников с учетом смещения
        for (int index : m_terrainTileIndices)
        {
            m_worldTriangleIndices.push_back(static_cast<int>(vertexOffset + index));
        }
    }
}

void NavMeshGenerator::processAdtWmos(const NavMeshTool::ADT::ADTData& adtData)
{
    // Проходим по каждому определению WMO, размещенному на этом ADT
    for (const auto& wmoDef : adtData.modfDefs)
    {
        // 1. Получаем имя файла WMO
        if (wmoDef.nameId >= adtData.wmoPaths.size())
        {
            qWarning(logNavMeshGenerator) << "Invalid WMO nameId:" << wmoDef.nameId;
            continue;
        }
        const std::string& wmoPath = adtData.wmoPaths[wmoDef.nameId];

        // 2. Читаем корневой WMO файл
        std::vector<unsigned char> wmoBuffer;
        if (!m_mpqManager.readFile(wmoPath, wmoBuffer))
        {
            qWarning(logNavMeshGenerator) << "Could not read WMO file:" << QString::fromStdString(wmoPath);
            continue;
        }

        // 3. Создаем fileProvider для парсера, чтобы он мог догружать доп. файлы (группы, M2 и т.д.)
        auto fileProvider = [this, &wmoPath](const std::string& filePath) -> std::optional<std::vector<unsigned char>>
        {
            std::string fullPath = filePath;

            // WMO-группы могут иметь относительные пути. Мы строим полный путь, используя путь к корневому WMO.
            // Doodads (M2) обычно имеют полный путь от корня MPQ.
            // Проверяем наличие разделителей пути, чтобы отличить их.
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

            // В файлах данных модели могут быть указаны с расширениями .MDX или .MDL,
            // но в MPQ-архивах они хранятся как .M2. Выполняем замену.
            std::string pathForMpq = fullPath;
            const auto extPos = pathForMpq.rfind('.');
            if (extPos != std::string::npos)
            {
                // Сравнение расширения без учета регистра.
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

            // Если чтение с заменой на .M2 не удалось, пробуем исходный путь.
            // Это может быть полезно для каких-то редких случаев или нестандартных файлов.
            if (pathForMpq != fullPath)
            {
                if (m_mpqManager.readFile(fullPath, buffer))
                {
                    return buffer;
                }
            }

            return std::nullopt;
        };

        // 4. Парсим WMO
        auto wmoDataOpt = m_wmoParser.parse(wmoPath, wmoBuffer, fileProvider);
        if (!wmoDataOpt)
        {
            qWarning(logNavMeshGenerator) << "Could not parse WMO file:" << QString::fromStdString(wmoPath);
            continue;
        }

        // 5. Трансформация и добавление геометрии
        const auto& wmoData = *wmoDataOpt;
        const size_t vertexOffset = m_worldVertices.size() / 3;

        // Матрица трансформации (согласно wowdev.wiki).
        // Координаты для WMO в чанке MODF являются "сырыми" и требуют
        // преобразования для получения мировых координат.
        const float posX = MAP_CHUNK_SIZE - wmoDef.position.y;
        const float posY = MAP_CHUNK_SIZE - wmoDef.position.x;
        const float posZ = wmoDef.position.z;

        const float rotX_rad = wmoDef.rotation.y * (PI / 180.0f);
        const float rotY_rad = wmoDef.rotation.z * (PI / 180.0f);
        const float rotZ_rad = wmoDef.rotation.x * (PI / 180.0f);

        for (const auto& wmoVert : wmoData.vertices)
        {
            // Конвертируем вершину из локальной системы координат модели (Y-up)
            // в локальную систему координат WoW (Z-up) перед вращением.
            // WoW X (юг)   = -Mod Y
            // WoW Y (запад) = -Mod X
            // WoW Z (вверх) =  Mod Z
            // Однако, судя по всему, модели экспортированы в левосторонней системе,
            // поэтому для корректного отображения используем следующую трансформацию:
            Vec3 vert = {-wmoVert.y, -wmoVert.x, wmoVert.z};

            // Применяем вращение (Z, Y, X)
            // Вращение вокруг Z
            float newX = vert.x * cos(rotZ_rad) - vert.y * sin(rotZ_rad);
            float newY = vert.x * sin(rotZ_rad) + vert.y * cos(rotZ_rad);
            vert.x = newX;
            vert.y = newY;

            // Вращение вокруг Y
            newX = vert.x * cos(rotY_rad) + vert.z * sin(rotY_rad);
            float newZ = -vert.x * sin(rotY_rad) + vert.z * cos(rotY_rad);
            vert.x = newX;
            vert.z = newZ;

            // Вращение вокруг X
            newY = vert.y * cos(rotX_rad) - vert.z * sin(rotX_rad);
            newZ = vert.y * sin(rotX_rad) + vert.z * cos(rotX_rad);
            vert.y = newY;
            vert.z = newZ;

            // Применяем позиционирование
            m_worldVertices.push_back(vert.x + posX);
            m_worldVertices.push_back(vert.y + posY);
            m_worldVertices.push_back(vert.z + posZ);
        }

        for (int index : wmoData.indices)
        {
            m_worldTriangleIndices.push_back(static_cast<int>(vertexOffset + index));
        }
    }
}

void NavMeshGenerator::processAdtM2s(const NavMeshTool::ADT::ADTData& adtData)
{
    // Проходим по каждому определению M2 (doodad), размещенному на этом ADT
    for (const auto& m2Def : adtData.mddfDefs)
    {
        // 1. Получаем имя файла M2
        if (m2Def.nameId >= adtData.doodadPaths.size())
        {
            qWarning(logNavMeshGenerator) << "Invalid M2 nameId:" << m2Def.nameId;
            continue;
        }
        const std::string& m2Path = adtData.doodadPaths[m2Def.nameId];

        // 2. Читаем файл модели M2
        // В файлах данных модели могут быть указаны с расширениями .MDX или .MDL,
        // но в MPQ-архивах они хранятся как .M2. Выполняем замену.
        std::string pathForMpq = m2Path;
        const auto extPos = pathForMpq.rfind('.');
        if (extPos != std::string::npos)
        {
            if (_stricmp(pathForMpq.c_str() + extPos, ".MDX") == 0 ||
                _stricmp(pathForMpq.c_str() + extPos, ".MDL") == 0)
            {
                pathForMpq.replace(extPos, 4, ".M2");
            }
        }

        std::vector<unsigned char> m2Buffer;
        if (!m_mpqManager.readFile(pathForMpq, m2Buffer))
        {
            // Попробуем прочитать с оригинальным путем, если с .M2 не вышло
            if (pathForMpq != m2Path && m_mpqManager.readFile(m2Path, m2Buffer))
            {
                // Успех, продолжаем
            }
            else
            {
                qWarning(logNavMeshGenerator) << "Could not read M2 file:" << QString::fromStdString(m2Path)
                                              << "(tried as" << QString::fromStdString(pathForMpq) << ")";
                continue;
            }
        }

        // 3. Парсим M2
        auto m2DataOpt = m_m2Parser.parse(m2Buffer);
        if (!m2DataOpt)
        {
            qWarning(logNavMeshGenerator) << "Could not parse M2 file:" << QString::fromStdString(pathForMpq);
            continue;
        }

        // 4. Трансформация и добавление геометрии
        const auto& m2Data = *m2DataOpt;
        const size_t vertexOffset = m_worldVertices.size() / 3;

        // Координаты для M2, как и для WMO, требуют преобразования.
        const float posX = MAP_CHUNK_SIZE - m2Def.position.y;
        const float posY = MAP_CHUNK_SIZE - m2Def.position.x;
        const float posZ = m2Def.position.z;

        const float rotX_rad = m2Def.rotation.y * (PI / 180.0f);
        const float rotY_rad = m2Def.rotation.z * (PI / 180.0f);
        const float rotZ_rad = m2Def.rotation.x * (PI / 180.0f);

        const float scaleFactor = static_cast<float>(m2Def.scale) / 1024.0f;

        for (const auto& m2Vert : m2Data.vertices)
        {
            // Конвертируем вершину из локальной системы координат модели
            // в локальную систему координат WoW (как и для WMO).
            Vec3 vert = {-m2Vert.y, -m2Vert.x, m2Vert.z};

            // Применяем масштаб
            vert.x *= scaleFactor;
            vert.y *= scaleFactor;
            vert.z *= scaleFactor;

            // Применяем вращение (Z, Y, X)
            // Вращение вокруг Z
            float newX = vert.x * cos(rotZ_rad) - vert.y * sin(rotZ_rad);
            float newY = vert.x * sin(rotZ_rad) + vert.y * cos(rotZ_rad);
            vert.x = newX;
            vert.y = newY;

            // Вращение вокруг Y
            newX = vert.x * cos(rotY_rad) + vert.z * sin(rotY_rad);
            float newZ = -vert.x * sin(rotY_rad) + vert.z * cos(rotY_rad);
            vert.x = newX;
            vert.z = newZ;

            // Вращение вокруг X
            newY = vert.y * cos(rotX_rad) - vert.z * sin(rotX_rad);
            newZ = vert.y * sin(rotX_rad) + vert.z * cos(rotX_rad);
            vert.y = newY;
            vert.z = newZ;

            // Применяем позиционирование
            m_worldVertices.push_back(vert.x + posX);
            m_worldVertices.push_back(vert.y + posY);
            m_worldVertices.push_back(vert.z + posZ);
        }

        for (int index : m2Data.indices)
        {
            m_worldTriangleIndices.push_back(static_cast<int>(vertexOffset + index));
        }
    }
}

void NavMeshGenerator::buildTerrainTileIndices()
{
    m_terrainTileIndices.clear();
    m_terrainTileIndices.reserve(8 * 8 * 4 * 3);  // 8x8 ячеек, 4 треугольника в каждой, 3 индекса на треугольник

    // Проходим по каждой ячейке 8x8
    for (int j = 0; j < 8; j++)
    {
        for (int i = 0; i < 8; i++)
        {
            // Индексы 4-х угловых вершин ячейки (внешние)
            const int v_top_left = j * 9 + i;
            const int v_top_right = v_top_left + 1;
            const int v_bottom_left = (j + 1) * 9 + i;
            const int v_bottom_right = v_bottom_left + 1;

            // Индекс центральной вершины ячейки (внутренняя)
            const int v_center = 81 + j * 8 + i;

            // Создаем 4 треугольника, которые сходятся в центре ячейки
            // Треугольник 1: верхний левый
            m_terrainTileIndices.push_back(v_top_left);
            m_terrainTileIndices.push_back(v_center);
            m_terrainTileIndices.push_back(v_bottom_left);

            // Треугольник 2: левый нижний
            m_terrainTileIndices.push_back(v_bottom_left);
            m_terrainTileIndices.push_back(v_center);
            m_terrainTileIndices.push_back(v_bottom_right);

            // Треугольник 3: нижний правый
            m_terrainTileIndices.push_back(v_bottom_right);
            m_terrainTileIndices.push_back(v_center);
            m_terrainTileIndices.push_back(v_top_right);

            // Треугольник 4: правый верхний
            m_terrainTileIndices.push_back(v_top_right);
            m_terrainTileIndices.push_back(v_center);
            m_terrainTileIndices.push_back(v_top_left);
        }
    }
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
