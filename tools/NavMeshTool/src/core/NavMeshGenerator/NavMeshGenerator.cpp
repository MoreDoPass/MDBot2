#include "NavMeshGenerator.h"
#include "core/MpqManager/MpqManager.h"  // Включаем для доступа к методам MpqManager
#include <QLoggingCategory>
#include <QDebug>
#include <cstring>  // Для memcpy или безопасного reinterpret_cast

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

bool NavMeshGenerator::loadMapData(const std::string& mapName, const std::vector<std::pair<int, int>>& /*adtCoords*/)
{
    qCInfo(logNavMeshGenerator) << "Loading map data for map:" << QString::fromStdString(mapName);

    // Очищаем данные от предыдущих запусков (если есть)
    m_worldVertices.clear();
    m_worldTriangleIndices.clear();

    // 1. Прочитать Map.dbc
    std::vector<unsigned char> mapDbcBuffer;
    std::string mapDbcPath = "DBFilesClient\\Map.dbc";  // Двойной слеш для C++ строк

    qCDebug(logNavMeshGenerator) << "Attempting to read" << QString::fromStdString(mapDbcPath);
    if (m_mpqManager.readFileToBuffer(mapDbcPath, mapDbcBuffer))
    {
        qCInfo(logNavMeshGenerator) << "Successfully read" << QString::fromStdString(mapDbcPath)
                                    << "into buffer, size:" << mapDbcBuffer.size() << "bytes.";
        parseMapDbc(mapDbcBuffer);
    }
    else
    {
        qCCritical(logNavMeshGenerator) << "Failed to read" << QString::fromStdString(mapDbcPath)
                                        << "from MPQ archives.";
        return false;  // Если не можем прочитать Map.dbc, дальнейшая загрузка карты невозможна
    }

    // Проверяем, были ли записи загружены из Map.dbc и найдена ли запрошенная карта
    if (m_mapDbcEntries.empty())
    {
        if (mapDbcBuffer.size() > 0)
        {  // Файл был прочитан, но парсер не нашел записей (или все были некорректны)
            qCWarning(logNavMeshGenerator)
                << "Map.dbc was read (size:" << mapDbcBuffer.size()
                << ") but no valid map entries were parsed. Cannot proceed with map loading for:"
                << QString::fromStdString(mapName);
        }
        else
        {  // Файл не был прочитан (уже залогировано выше, но для полноты)
            qCWarning(logNavMeshGenerator)
                << "Map.dbc could not be read and therefore no map entries were parsed. Cannot proceed.";
        }
        return false;
    }

    uint32_t targetMapId = 0;
    std::string targetMapDirectory;
    bool foundMapInDbc = false;

    for (const auto& entry : m_mapDbcEntries)
    {
        if (entry.second == mapName)
        {  // entry.second это directoryName
            targetMapId = entry.first;
            targetMapDirectory = entry.second;
            foundMapInDbc = true;
            qCInfo(logNavMeshGenerator) << "Found requested map in Map.dbc: ID:" << targetMapId
                                        << ", Directory:" << QString::fromStdString(targetMapDirectory);
            break;
        }
    }

    if (!foundMapInDbc)
    {
        qCWarning(logNavMeshGenerator) << "Map with directory name '" << QString::fromStdString(mapName)
                                       << "' not found in parsed Map.dbc data.";
        qCDebug(logNavMeshGenerator) << "Available maps in Map.dbc (" << m_mapDbcEntries.size() << " total):";
        int count = 0;
        for (const auto& entry : m_mapDbcEntries)
        {
            qCDebug(logNavMeshGenerator) << "  ID:" << entry.first << ", Dir: '" << QString::fromStdString(entry.second)
                                         << "'";
            if (++count >= 10 && m_mapDbcEntries.size() > 15)
            {  // Показываем первые несколько, если их много
                qCDebug(logNavMeshGenerator) << "...and" << (m_mapDbcEntries.size() - count) << "more.";
                break;
            }
        }
        return false;
    }

    // 2. Прочитать WDT файл для найденной карты
    std::string wdtFileName = "World\\Maps\\" + targetMapDirectory + "\\" + targetMapDirectory + ".wdt";
    qCInfo(logNavMeshGenerator) << "Attempting to read WDT file:" << QString::fromStdString(wdtFileName);

    std::vector<unsigned char> wdtBuffer;
    if (!m_mpqManager.readFileToBuffer(wdtFileName, wdtBuffer))
    {
        qCCritical(logNavMeshGenerator) << "Failed to read WDT file:" << QString::fromStdString(wdtFileName);
        return false;
    }

    qCInfo(logNavMeshGenerator) << "Successfully read WDT file" << QString::fromStdString(wdtFileName)
                                << "into buffer, size:" << wdtBuffer.size() << "bytes.";

    // Перед парсингом нового WDT, сбрасываем m_currentWdtData до состояния по умолчанию
    // Это очистит все векторы (adtFileNames, mwmoFilenames, modfEntries) и установит значения по умолчанию.
    m_currentWdtData = NavMeshTool::WDT::WDTData();
    m_currentWdtData.baseMapName = targetMapDirectory;  // Устанавливаем имя карты для генерации имен ADT

    qCDebug(logNavMeshGenerator) << "Parsing WDT data for" << QString::fromStdString(targetMapDirectory);
    if (!m_wdtParser.parse(reinterpret_cast<const char*>(wdtBuffer.data()), wdtBuffer.size(), m_currentWdtData))
    {
        qCCritical(logNavMeshGenerator) << "Failed to parse WDT data for map:"
                                        << QString::fromStdString(targetMapDirectory);
        return false;
    }

    qCInfo(logNavMeshGenerator) << "WDT data parsed successfully for map:"
                                << QString::fromStdString(targetMapDirectory);
    qCInfo(logNavMeshGenerator) << "  WDT Version:" << m_currentWdtData.version;
    qCInfo(logNavMeshGenerator) << "  MPHD Flags:" << Qt::hex << m_currentWdtData.mphd.flags;
    qCInfo(logNavMeshGenerator) << "  MPHD wdtEntryId/something:" << m_currentWdtData.mphd.wdtEntryId;
    qCInfo(logNavMeshGenerator) << "  Global WMOs (MWMO):" << m_currentWdtData.mwmoFilenames.size();
    qCInfo(logNavMeshGenerator) << "  Global WMO placements (MODF):" << m_currentWdtData.modfEntries.size();
    qCInfo(logNavMeshGenerator) << "  Number of ADT files to load (based on MAIN flags):"
                                << m_currentWdtData.adtFileNames.size();

    if (m_currentWdtData.adtFileNames.empty())
    {
        qCWarning(logNavMeshGenerator) << "No ADT files marked for loading in WDT for map:"
                                       << QString::fromStdString(targetMapDirectory)
                                       << "(MAIN chunk might indicate an empty map or all ADTs are missing flags).";
        // Для некоторых карт (например, тестовых или очень маленьких инстансов) это может быть нормально.
        // Но для больших карт, как Azeroth, это было бы странно.
    }

    // TODO: Реализовать логику загрузки ADT файлов на основе m_currentWdtData.adtFileNames
    // TODO: Реализовать логику загрузки WMO, M2 файлов и сбора геометрии

    qCInfo(logNavMeshGenerator) << "Map.dbc and WDT processed successfully for map:"
                                << QString::fromStdString(targetMapDirectory) << "(ID:" << targetMapId
                                << "). Further geometry loading (ADT, etc.) not yet implemented.";
    return true;  // Возвращаем true, так как Map.dbc и WDT обработаны и карта найдена
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

}  // namespace NavMesh
