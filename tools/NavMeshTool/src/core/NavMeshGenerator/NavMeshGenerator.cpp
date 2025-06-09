#include "NavMeshGenerator.h"
#include "core/MpqManager/MpqManager.h"  // Включаем для доступа к методам MpqManager
#include <QLoggingCategory>
#include <QDebug>
#include <cstring>  // Для memcpy или безопасного reinterpret_cast
#include <string>

// Пока что MpqManager.h не нужен здесь, так как мы работаем только со ссылкой,
// а все вызовы будут через m_mpqManager, тип которой уже известен из NavMeshGenerator.h
// #include "../../MpqManager/MpqManager.h" // Если бы мы создавали MpqManager здесь или использовали его конкретные
// типы

// #include <iostream>  // Заменяем на Qt логгер

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

    qInfo(logNavMeshGenerator) << "Finished processing all ADTs for map" << QString::fromStdString(mapName);
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
    qCDebug(logNavMeshGenerator) << "Parsing Map.dbc, buffer size:" << buffer.size();
    m_mapDbcEntries.clear();  // Очищаем предыдущие данные

    if (buffer.empty())
    {
        qCWarning(logNavMeshGenerator) << "Map.dbc buffer is empty, nothing to parse.";
        return;
    }

    const size_t headerSize = 20;  // Размер заголовка DBC (4sIIII = 4 + 4*4 = 20 байт)
    if (buffer.size() < headerSize)
    {
        qCWarning(logNavMeshGenerator) << "Map.dbc buffer is too small for a header.";
        return;
    }

    // 1. Заголовок (DBCHeader)
    const char* dataPtr = reinterpret_cast<const char*>(buffer.data());

    // Проверка сигнатуры 'WDBC'
    if (std::strncmp(dataPtr, "WDBC", 4) != 0)
    {
        qCWarning(logNavMeshGenerator) << "Invalid Map.dbc signature. Expected 'WDBC', got:"
                                       << QString::fromLatin1(dataPtr, 4);
        return;
    }

    uint32_t recordCount = 0;
    uint32_t fieldCount = 0;  // Не используется напрямую для Map.dbc, но полезно для общей структуры DBC
    uint32_t recordSize = 0;
    uint32_t stringBlockSize = 0;

    std::memcpy(&recordCount, dataPtr + 4, sizeof(uint32_t));
    std::memcpy(&fieldCount, dataPtr + 8, sizeof(uint32_t));
    std::memcpy(&recordSize, dataPtr + 12, sizeof(uint32_t));
    std::memcpy(&stringBlockSize, dataPtr + 16, sizeof(uint32_t));

    qCDebug(logNavMeshGenerator) << "Map.dbc Header: Records:" << recordCount << ", Fields:" << fieldCount
                                 << ", RecordSize:" << recordSize << ", StringBlockSize:" << stringBlockSize;

    if (recordSize == 0)
    {
        qCWarning(logNavMeshGenerator) << "Map.dbc record_size is 0. Cannot parse records.";
        return;
    }

    // Проверка, что размеры в заголовке не приводят к выходу за пределы буфера
    size_t expectedTotalSize = headerSize + (static_cast<size_t>(recordCount) * recordSize) + stringBlockSize;
    if (expectedTotalSize > buffer.size())
    {
        qCWarning(logNavMeshGenerator) << "Map.dbc header indicates data size (" << expectedTotalSize
                                       << ") larger than buffer size (" << buffer.size() << "). Possible corruption.";
        // Можно попытаться продолжить, если stringBlockSize кажется разумным и есть хотя бы блок записей
        // Но для начала лучше остановиться.
        return;
    }

    const char* recordBlockPtr = dataPtr + headerSize;
    const char* stringBlockPtr = dataPtr + headerSize + (static_cast<size_t>(recordCount) * recordSize);

    qCDebug(logNavMeshGenerator) << "Processing" << recordCount << "records.";

    for (uint32_t i = 0; i < recordCount; ++i)
    {
        const char* currentRecordPtr = recordBlockPtr + (static_cast<size_t>(i) * recordSize);

        // Проверяем, что мы не вышли за пределы блока записей (хотя header check должен был это покрыть)
        if (static_cast<size_t>((currentRecordPtr + recordSize) - dataPtr) >
            headerSize + (static_cast<size_t>(recordCount) * recordSize))
        {
            qCWarning(logNavMeshGenerator) << "Attempting to read past record block at record index" << i;
            break;
        }

        // В Map.dbc (3.3.5a):
        // Поле 0 (смещение 0): uint32_t map_id
        // Поле 1 (смещение 4): uint32_t directory_offset (смещение в string_block)
        // ... другие поля, нас интересуют первые два

        if (recordSize < 8)
        {  // Нам нужны как минимум ID и offset
            qCWarning(logNavMeshGenerator)
                << "Record size" << recordSize << "is too small to contain map_id and directory_offset at record index"
                << i;
            continue;  // Пропускаем эту запись
        }

        uint32_t mapId = 0;
        uint32_t directoryOffset = 0;

        std::memcpy(&mapId, currentRecordPtr, sizeof(uint32_t));
        std::memcpy(&directoryOffset, currentRecordPtr + 4, sizeof(uint32_t));

        if (directoryOffset >= stringBlockSize)
        {
            qCWarning(logNavMeshGenerator)
                << "MapID:" << mapId << "- Invalid directory_offset:" << directoryOffset
                << "(String block size:" << stringBlockSize << "). Skipping record index" << i;
            continue;
        }

        // Проверяем, что сам stringBlockPtr + directoryOffset не выходит за пределы всего буфера
        if (static_cast<size_t>((stringBlockPtr + directoryOffset) - dataPtr) >= buffer.size())
        {
            qCWarning(logNavMeshGenerator) << "MapID:" << mapId << "- Directory_offset:" << directoryOffset
                                           << "points outside of the provided buffer. Skipping record index" << i;
            continue;
        }

        std::string directoryName(stringBlockPtr + directoryOffset);  // std::string сам найдет конец строки ('\0')

        m_mapDbcEntries[mapId] = directoryName;
        // qCDebug(logNavMeshGenerator) << "MapID:" << mapId << ", Directory: '" <<
        // QString::fromStdString(directoryName) << "'";
    }

    qCInfo(logNavMeshGenerator) << "Map.dbc parsing complete. Found" << m_mapDbcEntries.size() << "map entries.";
    if (recordCount > 0 && m_mapDbcEntries.empty() && recordSize >= 8)
    {
        qCWarning(logNavMeshGenerator) << "Parsed 0 entries but recordCount was" << recordCount
                                       << ". Check logic or DBC content.";
    }
}

void NavMeshGenerator::processAdtChunk(const NavMeshTool::ADT::ADTData& adtData, int row, int col)
{
    Q_UNUSED(adtData);
    Q_UNUSED(row);
    Q_UNUSED(col);
    // Эта функция будет реализована в следующих шагах согласно TODO.md
    // 1. processAdtTerrain(...)
    // 2. processAdtWmos(...)
    // 3. processAdtM2s(...)
}

}  // namespace NavMesh
