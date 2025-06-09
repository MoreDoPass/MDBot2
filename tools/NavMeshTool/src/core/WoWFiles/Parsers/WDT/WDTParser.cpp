#include "WDTParser.h"

#include <cstring>    // Для memcpy, memcmp
#include <stdexcept>  // Для std::runtime_error (пример)
#include <vector>     // Для std::vector

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

bool Parser::readChunkHeader(const unsigned char*& currentPtr, size_t& remainingSize, ChunkHeader& outHeader) const
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

bool Parser::parseMVER(const unsigned char*& currentPtr, size_t& remainingSize, WDTData& outWDTData) const
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

bool Parser::parseMPHD(const unsigned char*& currentPtr, size_t& remainingSize, WDTData& outWDTData) const
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

bool Parser::parseMAIN(const unsigned char*& currentPtr, size_t& remainingSize, WDTData& outWDTData) const
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

bool Parser::parseMWMO(const unsigned char*& currentPtr, size_t& remainingSize, const ChunkHeader& mwmoHeader,
                       WDTData& outWDTData) const
{
    if (remainingSize < mwmoHeader.size)
    {
        qCWarning(logWdtParser) << "MWMO: Chunk size mismatch or not enough data. Header size:" << mwmoHeader.size
                                << "Remaining:" << remainingSize;
        return false;
    }

    const unsigned char* mwmoDataStart = currentPtr;
    const unsigned char* mwmoDataEnd = currentPtr + mwmoHeader.size;

    outWDTData.mwmoFilenames.clear();
    const char* nameStart = reinterpret_cast<const char*>(mwmoDataStart);
    for (const unsigned char* p = mwmoDataStart; p < mwmoDataEnd; ++p)
    {
        if (*p == '\0')
        {
            if (reinterpret_cast<const char*>(p) > nameStart)
            {
                outWDTData.mwmoFilenames.emplace_back(nameStart);
            }
            nameStart = reinterpret_cast<const char*>(p + 1);
        }
    }
    if (nameStart < reinterpret_cast<const char*>(mwmoDataEnd) && *nameStart != '\0')
    {
        outWDTData.mwmoFilenames.emplace_back(nameStart);
    }

    currentPtr += mwmoHeader.size;
    remainingSize -= mwmoHeader.size;
    qCDebug(logWdtParser) << "Parsed MWMO chunk, found" << outWDTData.mwmoFilenames.size() << "filenames.";
    return true;
}

bool Parser::parseMODF(const unsigned char*& currentPtr, size_t& remainingSize, const ChunkHeader& modfHeader,
                       WDTData& outWDTData) const
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

std::optional<WDTData> Parser::parse(const std::vector<unsigned char>& dataBuffer, const std::string& mapName) const
{
    if (dataBuffer.empty())
    {
        qCWarning(logWdtParser) << "Parse called with no data.";
        return std::nullopt;
    }

    qCInfo(logWdtParser) << "Starting WDT parsing for map" << QString::fromStdString(mapName)
                         << ". Total size:" << dataBuffer.size();

    WDTData wdtData;
    wdtData.baseMapName = mapName;

    const unsigned char* currentPtr = dataBuffer.data();
    size_t remainingSize = dataBuffer.size();

    bool mverFound = false;
    bool mphdFound = false;
    bool mainFound = false;

    ChunkHeader header;

    if (!readChunkHeader(currentPtr, remainingSize, header)) return std::nullopt;
    if (header.isValid("REVM"))
    {
        if (!parseMVER(currentPtr, remainingSize, wdtData)) return std::nullopt;
        mverFound = true;
    }
    else
    {
        qCCritical(logWdtParser) << "First chunk is not MVER (expected REVM). Signature:"
                                 << QString::fromLatin1(header.signature, 4);
        return std::nullopt;
    }

    if (!readChunkHeader(currentPtr, remainingSize, header)) return std::nullopt;
    if (header.isValid("DHPM"))
    {
        if (!parseMPHD(currentPtr, remainingSize, wdtData)) return std::nullopt;
        mphdFound = true;
    }
    else
    {
        qCCritical(logWdtParser) << "Second chunk is not MPHD (expected DHPM). Signature:"
                                 << QString::fromLatin1(header.signature, 4);
        return std::nullopt;
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
            if (!parseMAIN(currentPtr, remainingSize, wdtData)) return std::nullopt;
            mainFound = true;
        }
        else if (header.isValid("OMWM"))
        {
            if (!(wdtData.mphd.flags & 0x1))
            {
                qCWarning(logWdtParser)
                    << "Found MWMO (OMWM) chunk, but wdt_uses_global_map_obj flag is not set in MPHD!";
            }
            if (!parseMWMO(currentPtr, remainingSize, header, wdtData)) return std::nullopt;
        }
        else if (header.isValid("FDOM"))
        {
            if (!(wdtData.mphd.flags & 0x1))
            {
                qCWarning(logWdtParser)
                    << "Found MODF (FDOM) chunk, but wdt_uses_global_map_obj flag is not set in MPHD!";
            }
            if (!parseMODF(currentPtr, remainingSize, header, wdtData)) return std::nullopt;
        }
        else
        {
            qCDebug(logWdtParser) << "Skipping unknown or unhandled chunk:" << QString::fromLatin1(header.signature, 4);
            if (remainingSize < header.size)
            {
                qCWarning(logWdtParser) << "Cannot skip chunk, not enough data. Chunk size:" << header.size
                                        << "Remaining:" << remainingSize;
                return std::nullopt;
            }
            currentPtr += header.size;
            remainingSize -= header.size;
        }
    }

    if (!mverFound || !mphdFound || !mainFound)
    {
        qCCritical(logWdtParser) << "Parsing failed: one or more mandatory chunks (MVER, MPHD, MAIN) not found."
                                 << "MVER:" << mverFound << "MPHD:" << mphdFound << "MAIN:" << mainFound;
        return std::nullopt;
    }

    // Генерация имен ADT файлов, если MAIN чанк был найден и обработан
    if (mainFound)  // baseMapName теперь всегда установлен
    {
        for (size_t i = 0; i < WDT_MAIN_ENTRIES_COUNT; ++i)
        {
            if (wdtData.mainEntries[i].flags & SMAREA_FLAG_HAS_ADT)
            {
                int tileX = i % 64;  // Согласно wowdev: TileX = index % 64
                int tileY = i / 64;  // Согласно wowdev: TileY = index / 64

                // Формат имени: World\maps\MapName\MapName_tileY_tileX.adt
                std::string adtPath = "World\\maps\\" + wdtData.baseMapName + "\\" + wdtData.baseMapName + "_" +
                                      std::to_string(tileY) + "_" + std::to_string(tileX) + ".adt";

                wdtData.adtFilenames.push_back({adtPath, tileX, tileY});
            }
        }
        qCDebug(logWdtParser) << "Generated" << wdtData.adtFilenames.size() << "ADT filenames for map"
                              << QString::fromStdString(wdtData.baseMapName);
    }

    qCInfo(logWdtParser) << "WDT parsing finished successfully for map" << QString::fromStdString(wdtData.baseMapName);
    return wdtData;
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
