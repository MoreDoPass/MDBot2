#include "WDTParser.h"

#include <cstring>    // Для memcpy, memcmp
#include <stdexcept>  // Для std::runtime_error (пример)

#include <QDebug>  // Для qDebug, qWarning и т.д.

// Определяем категорию логирования
// Имя "navmesh.core.wowfiles.wdtparser" позволит гибко настраивать вывод логов
Q_LOGGING_CATEGORY(logWdtParser, "navmesh.core.wowfiles.wdtparser")

namespace NavMeshTool
{
namespace WDT
{

Parser::Parser()
{
    // Конструктор
    qCDebug(logWdtParser) << "WDT Parser created";
}

Parser::~Parser()
{
    // Деструктор
    qCDebug(logWdtParser) << "WDT Parser destroyed";
}

bool Parser::readChunkHeader(const char*& currentPtr, size_t& remainingSize, ChunkHeader& outHeader)
{
    if (remainingSize < SIZEOF_CHUNK_HEADER)
    {
        qCWarning(logWdtParser) << "Not enough data to read chunk header. Remaining:" << remainingSize;
        return false;
    }
    memcpy(&outHeader, currentPtr, SIZEOF_CHUNK_HEADER);
    currentPtr += SIZEOF_CHUNK_HEADER;
    remainingSize -= SIZEOF_CHUNK_HEADER;
    return true;
}

bool Parser::parseMVER(const char*& currentPtr, size_t& remainingSize, WDTData& outWDTData)
{
    if (remainingSize < sizeof(uint32_t))
    {
        qCWarning(logWdtParser) << "MVER: Not enough data for version. Remaining:" << remainingSize;
        return false;
    }
    memcpy(&outWDTData.version, currentPtr, sizeof(uint32_t));
    currentPtr += sizeof(uint32_t);
    remainingSize -= sizeof(uint32_t);
    qCDebug(logWdtParser) << "Parsed MVER: version" << outWDTData.version;
    return true;
}

bool Parser::parseMPHD(const char*& currentPtr, size_t& remainingSize, WDTData& outWDTData)
{
    if (remainingSize < sizeof(MPHDChunk))
    {
        qCWarning(logWdtParser) << "MPHD: Not enough data for header. Remaining:" << remainingSize;
        return false;
    }
    memcpy(&outWDTData.mphd, currentPtr, sizeof(MPHDChunk));
    currentPtr += sizeof(MPHDChunk);
    remainingSize -= sizeof(MPHDChunk);
    qCDebug(logWdtParser) << "Parsed MPHD: flags" << Qt::hex << outWDTData.mphd.flags
                          << "id:" << outWDTData.mphd.wdtEntryId;
    return true;
}

bool Parser::parseMAIN(const char*& currentPtr, size_t& remainingSize, WDTData& outWDTData)
{
    const size_t expectedMainSize = WDT_MAIN_ENTRIES_COUNT * sizeof(SMAreaInfo);
    if (remainingSize < expectedMainSize)
    {
        qCWarning(logWdtParser) << "MAIN: Not enough data. Expected:" << expectedMainSize
                                << "Remaining:" << remainingSize;
        return false;
    }
    memcpy(outWDTData.mainEntries.data(), currentPtr, expectedMainSize);
    currentPtr += expectedMainSize;
    remainingSize -= expectedMainSize;
    qCDebug(logWdtParser) << "Parsed MAIN chunk with" << WDT_MAIN_ENTRIES_COUNT << "entries.";
    return true;
}

bool Parser::parseMWMO(const char*& currentPtr, size_t& remainingSize, const ChunkHeader& mwmoHeader,
                       WDTData& outWDTData)
{
    if (remainingSize < mwmoHeader.size)
    {
        qCWarning(logWdtParser) << "MWMO: Chunk size mismatch or not enough data. Header size:" << mwmoHeader.size
                                << "Remaining:" << remainingSize;
        return false;
    }

    const char* mwmoDataStart = currentPtr;
    const char* mwmoDataEnd = currentPtr + mwmoHeader.size;

    outWDTData.mwmoFilenames.clear();
    const char* nameStart = mwmoDataStart;
    for (const char* p = mwmoDataStart; p < mwmoDataEnd; ++p)
    {
        if (*p == '\0')
        {
            if (p > nameStart)
            {
                outWDTData.mwmoFilenames.emplace_back(nameStart);
            }
            nameStart = p + 1;
        }
    }
    if (nameStart < mwmoDataEnd && *nameStart != '\0')
    {
        outWDTData.mwmoFilenames.emplace_back(nameStart);
    }

    currentPtr += mwmoHeader.size;
    remainingSize -= mwmoHeader.size;
    qCDebug(logWdtParser) << "Parsed MWMO chunk, found" << outWDTData.mwmoFilenames.size() << "filenames.";
    return true;
}

bool Parser::parseMODF(const char*& currentPtr, size_t& remainingSize, const ChunkHeader& modfHeader,
                       WDTData& outWDTData)
{
    if (remainingSize < modfHeader.size)
    {
        qCWarning(logWdtParser) << "MODF: Chunk size mismatch or not enough data. Header size:" << modfHeader.size
                                << "Remaining:" << remainingSize;
        return false;
    }
    if (modfHeader.size % sizeof(MODFEntry) != 0)
    {
        qCWarning(logWdtParser) << "MODF: Chunk size" << modfHeader.size << "is not a multiple of MODFEntry size"
                                << sizeof(MODFEntry);
        return false;
    }

    size_t numEntries = modfHeader.size / sizeof(MODFEntry);
    outWDTData.modfEntries.resize(numEntries);
    memcpy(outWDTData.modfEntries.data(), currentPtr, modfHeader.size);

    currentPtr += modfHeader.size;
    remainingSize -= modfHeader.size;
    qCDebug(logWdtParser) << "Parsed MODF chunk with" << numEntries << "entries.";
    return true;
}

bool Parser::parse(const char* data, size_t size, WDTData& outWDTData)
{
    if (!data || size == 0)
    {
        qCWarning(logWdtParser) << "Parse called with no data.";
        return false;
    }

    qCInfo(logWdtParser) << "Starting WDT parsing. Total size:" << size;

    const char* currentPtr = data;
    size_t remainingSize = size;

    // Перед началом парсинга убедимся, что имя базовой карты установлено в outWDTData.
    // Это должно быть сделано вызывающей стороной.
    if (outWDTData.baseMapName.empty())
    {
        qCWarning(logWdtParser)
            << "Base map name is not set in WDTData. ADT filenames might be incorrect or not generated.";
        // Можно либо вернуть false, либо продолжить без генерации имен ADT, либо генерировать с плейсхолдером.
        // Пока что просто выведем предупреждение и продолжим.
    }
    outWDTData.adtFileNames.clear();  // Очищаем список имен ADT файлов

    bool mverFound = false;
    bool mphdFound = false;
    bool mainFound = false;

    ChunkHeader header;

    if (!readChunkHeader(currentPtr, remainingSize, header)) return false;
    if (header.isValid("REVM"))
    {
        if (!parseMVER(currentPtr, remainingSize, outWDTData)) return false;
        mverFound = true;
    }
    else
    {
        qCCritical(logWdtParser) << "First chunk is not MVER (expected REVM). Signature:"
                                 << QString::fromLatin1(header.signature, 4);
        return false;
    }

    if (!readChunkHeader(currentPtr, remainingSize, header)) return false;
    if (header.isValid("DHPM"))
    {
        if (!parseMPHD(currentPtr, remainingSize, outWDTData)) return false;
        mphdFound = true;
    }
    else
    {
        qCCritical(logWdtParser) << "Second chunk is not MPHD (expected DHPM). Signature:"
                                 << QString::fromLatin1(header.signature, 4);
        return false;
    }

    while (remainingSize >= SIZEOF_CHUNK_HEADER)
    {
        if (!readChunkHeader(currentPtr, remainingSize, header))
        {
            qCWarning(logWdtParser) << "Could not read next chunk header. Remaining size:" << remainingSize;
            break;
        }

        qCDebug(logWdtParser) << "Found chunk:" << QString::fromLatin1(header.signature, 4) << "Size:" << header.size;

        if (header.isValid("NIAM"))
        {
            if (!parseMAIN(currentPtr, remainingSize, outWDTData)) return false;
            mainFound = true;
        }
        else if (header.isValid("OMWM"))
        {
            if (!(outWDTData.mphd.flags & 0x1))
            {
                qCWarning(logWdtParser)
                    << "Found MWMO (OMWM) chunk, but wdt_uses_global_map_obj flag is not set in MPHD!";
            }
            if (!parseMWMO(currentPtr, remainingSize, header, outWDTData)) return false;
        }
        else if (header.isValid("FDOM"))
        {
            if (!(outWDTData.mphd.flags & 0x1))
            {
                qCWarning(logWdtParser)
                    << "Found MODF (FDOM) chunk, but wdt_uses_global_map_obj flag is not set in MPHD!";
            }
            if (!parseMODF(currentPtr, remainingSize, header, outWDTData)) return false;
        }
        else
        {
            qCDebug(logWdtParser) << "Skipping unknown or unhandled chunk:" << QString::fromLatin1(header.signature, 4);
            if (remainingSize < header.size)
            {
                qCWarning(logWdtParser) << "Cannot skip chunk, not enough data. Chunk size:" << header.size
                                        << "Remaining:" << remainingSize;
                return false;
            }
            currentPtr += header.size;
            remainingSize -= header.size;
        }
    }

    if (!mverFound || !mphdFound || !mainFound)
    {
        qCCritical(logWdtParser) << "Parsing failed: one or more mandatory chunks (MVER, MPHD, MAIN) not found."
                                 << "MVER:" << mverFound << "MPHD:" << mphdFound << "MAIN:" << mainFound;
        return false;
    }

    // Генерация имен ADT файлов, если MAIN чанк был найден и обработан
    if (mainFound && !outWDTData.baseMapName.empty())
    {
        for (size_t i = 0; i < WDT_MAIN_ENTRIES_COUNT; ++i)
        {
            if (outWDTData.mainEntries[i].flags & SMAREA_FLAG_HAS_ADT)
            {
                int tileFileX = i / 64;  // Согласно README: FileX = index / 64
                int tileFileY = i % 64;  // Согласно README: FileY = index % 64
                // Корректный формат имени: MapName_FileY_FileX.adt
                std::string adtName = outWDTData.baseMapName + "_" + std::to_string(tileFileY) +
                                      "_" +                                // Сначала FileY (index % 64)
                                      std::to_string(tileFileX) + ".adt";  // Затем FileX (index / 64)
                outWDTData.adtFileNames.push_back(adtName);
            }
        }
        qCDebug(logWdtParser) << "Generated" << outWDTData.adtFileNames.size() << "ADT filenames for map"
                              << QString::fromStdString(outWDTData.baseMapName);
    }
    else if (mainFound && outWDTData.baseMapName.empty())
    {
        qCWarning(logWdtParser) << "MAIN chunk found, but baseMapName is empty. Cannot generate ADT filenames.";
    }

    qCInfo(logWdtParser) << "WDT parsing finished successfully.";
    return true;
}

/*
bool Parser::parseFromFile(const std::string& filePath, WDTData& outWDTData) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        qCWarning(logWdtParser) << "Failed to open WDT file:" << QString::fromStdString(filePath);
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        qCWarning(logWdtParser) << "Failed to read WDT file:" << QString::fromStdString(filePath);
        return false;
    }

    return parse(buffer.data(), buffer.size(), outWDTData);
}
*/

}  // namespace WDT
}  // namespace NavMeshTool
