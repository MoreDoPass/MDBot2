#include "ADTParser.h"
#include <iostream>  // Для std::cerr, std::cout
#include <vector>
#include <string_view>  // Для constexpr ID чанков
#include <algorithm>    // Для std::equal
#include <sstream>      // Для std::istringstream
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(log_adt_parser, "adt.parser", QtWarningMsg)

namespace NavMeshTool::ADT
{

// Вспомогательная функция для сравнения ID чанков (char[4] с const char*)
// Не чувствительна к порядку байт в chunkIdFromFile, он должен быть как в файле (перевернут)
bool compareChunkId(const char chunkIdFromFile[4], const char* expectedReversedId)
{
    return chunkIdFromFile[0] == expectedReversedId[0] && chunkIdFromFile[1] == expectedReversedId[1] &&
           chunkIdFromFile[2] == expectedReversedId[2] && chunkIdFromFile[3] == expectedReversedId[3];
}

void Parser::log(const std::string& message, std::vector<std::string>& logMessages)
{
    logMessages.push_back(message);
}

bool Parser::readChunkHeader(std::istream& stream, ChunkHeader& header)
{
    stream.read(reinterpret_cast<char*>(&header), sizeof(ChunkHeader));
    if (!stream || stream.gcount() != sizeof(ChunkHeader))
    {
        // Не логируем здесь, т.к. это может быть нормальным концом файла
        return false;
    }
    return true;
}

template <typename T>
bool Parser::readChunkData(std::istream& stream, uint32_t dataSize, T& dataStruct)
{
    if (dataSize != sizeof(T))
    {
        stream.seekg(dataSize, std::ios::cur);
        return false;
    }
    stream.read(reinterpret_cast<char*>(&dataStruct), sizeof(T));
    return stream && stream.gcount() == sizeof(T);
}

// Реализация parseMVER
bool Parser::parseMVER(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    ChunkHeader mverHeader;
    if (!readChunkHeader(stream, mverHeader))
    {
        log("[ERROR] Failed to read MVER header.", logMessages);
        return false;
    }

    if (!compareChunkId(mverHeader.chunkId, MVER_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MVER chunk ID mismatch. Found: " + std::string(mverHeader.chunkId, 4), logMessages);
        return false;
    }

    if (mverHeader.dataSize != sizeof(MVERData))
    {
        log("[ERROR] MVER data size mismatch. Expected " + std::to_string(sizeof(MVERData)) + ", got " +
                std::to_string(mverHeader.dataSize),
            logMessages);
        stream.seekg(mverHeader.dataSize, std::ios::cur);  // Попытка пропустить данные
        return false;
    }

    if (!readChunkData(stream, mverHeader.dataSize, adtData.mver)) return false;

    if (adtData.mver.version != 18)
    {
        log("[WARNING] MVER version is not 18. Version: " + std::to_string(adtData.mver.version), logMessages);
        // Продолжаем, но это может быть проблемой для WotLK.
    }
    log("MVER: Version " + std::to_string(adtData.mver.version) + " successfully parsed.", logMessages);
    return true;
}

// Реализация parseMHDR
bool Parser::parseMHDR(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    ChunkHeader mhdrHeader;
    if (!readChunkHeader(stream, mhdrHeader))
    {
        log("[ERROR] Failed to read MHDR header.", logMessages);
        return false;
    }

    if (!compareChunkId(mhdrHeader.chunkId, MHDR_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MHDR chunk ID mismatch. Found: " + std::string(mhdrHeader.chunkId, 4), logMessages);
        return false;
    }

    if (mhdrHeader.dataSize != sizeof(MHDRData))
    {
        log("[ERROR] MHDR data size mismatch. Expected " + std::to_string(sizeof(MHDRData)) + ", got " +
                std::to_string(mhdrHeader.dataSize),
            logMessages);
        stream.seekg(mhdrHeader.dataSize, std::ios::cur);  // Попытка пропустить данные
        return false;
    }

    // Смещение MHDR данных от начала файла всегда 20 байт (12 MVER + 8 заголовок MHDR).
    constexpr uint32_t MVER_CHUNK_TOTAL_SIZE = 12;
    constexpr uint32_t MHDR_CHUNK_HEADER_SIZE = 8;
    constexpr uint32_t mhdrDataBlockStartOffset = MVER_CHUNK_TOTAL_SIZE + MHDR_CHUNK_HEADER_SIZE;  // 20

    if (!readChunkData(stream, mhdrHeader.dataSize, adtData.mhdr)) return false;

    // Корректируем смещения, чтобы они стали абсолютными (от начала файла).
    if (adtData.mhdr.offsetMCIN != 0) adtData.mhdr.offsetMCIN += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMTEX != 0) adtData.mhdr.offsetMTEX += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMMDX != 0) adtData.mhdr.offsetMMDX += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMMID != 0) adtData.mhdr.offsetMMID += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMWMO != 0) adtData.mhdr.offsetMWMO += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMWID != 0) adtData.mhdr.offsetMWID += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMDDF != 0) adtData.mhdr.offsetMDDF += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMODF != 0) adtData.mhdr.offsetMODF += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMFBO != 0) adtData.mhdr.offsetMFBO += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMH2O != 0) adtData.mhdr.offsetMH2O += mhdrDataBlockStartOffset;
    if (adtData.mhdr.offsetMTXF != 0) adtData.mhdr.offsetMTXF += mhdrDataBlockStartOffset;

    log("MHDR: Successfully parsed and offsets adjusted. Absolute OffsetMCIN: " +
            std::to_string(adtData.mhdr.offsetMCIN) +
            ", Absolute OffsetMTEX: " + std::to_string(adtData.mhdr.offsetMTEX),
        logMessages);
    return true;
}

// Реализация parseMCIN
// mhdrDataBlockStartFileOffset - это абсолютное смещение в файле, где начинаются данные MHDR (после заголовка MHDR)
// В нашем случае MHDR всегда 64 байта, и его данные начинаются после MVER (12 байт) + заголовка MHDR (8 байт)
// т.е. 12 + 8 = 20 байт от начала файла.
bool Parser::parseMCIN(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    if (adtData.mhdr.offsetMCIN == 0)
    {
        log("[WARNING] MHDR.offsetMCIN is 0. MCIN chunk will be skipped.", logMessages);
        return true;  // Не ошибка, просто нет MCIN
    }

    ChunkHeader mcinHeader;
    if (!readChunkHeader(stream, mcinHeader))
    {
        log("[ERROR] Failed to read MCIN header.", logMessages);
        return false;
    }

    if (!compareChunkId(mcinHeader.chunkId, MCIN_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MCIN chunk ID mismatch. ADT: " + adtData.adtSourceName + ". Found: " +
                std::string(mcinHeader.chunkId, 4) + ", Expected: " + std::string(MCIN_CHUNK_ID_REVERSED, 4),
            logMessages);
        return false;
    }

    constexpr uint32_t expectedMcInDataSize = 256 * sizeof(MCINEntry);  // 256 * 16 = 4096
    if (mcinHeader.dataSize != expectedMcInDataSize)
    {
        log("[ERROR] MCIN data size mismatch. Expected " + std::to_string(expectedMcInDataSize) + ", got " +
                std::to_string(mcinHeader.dataSize),
            logMessages);
        stream.seekg(mcinHeader.dataSize, std::ios::cur);
        return false;
    }

    stream.read(reinterpret_cast<char*>(adtData.mcinEntries.data()), expectedMcInDataSize);
    if (!stream || stream.gcount() != expectedMcInDataSize)
    {
        log("[ERROR] Failed to read MCIN entries data.", logMessages);
        return false;
    }

    log("MCIN: Successfully parsed " + std::to_string(adtData.mcinEntries.size()) + " entries.", logMessages);
    return true;
}

// Реализация parseMCRF
bool Parser::parseMCRF(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset,
                       std::vector<std::string>& logMessages)
{
    if (mcnkChunk.header.ofsRefs == 0)
    {
        if (mcnkChunk.header.nDoodadRefs == 0 && mcnkChunk.header.nMapObjRefs == 0)
        {
            // Нормальная ситуация
        }
        else
        {
            log("[WARNING] MCRF Offset is 0, but nDoodadRefs=" + std::to_string(mcnkChunk.header.nDoodadRefs) +
                    ", nMapObjRefs=" + std::to_string(mcnkChunk.header.nMapObjRefs) + ".",
                logMessages);
        }
        return true;  // Не ошибка, просто нет MCRF
    }

    uint32_t absoluteMcrfOffset = mcnkBaseOffset + mcnkChunk.header.ofsRefs;
    std::streampos originalPos = stream.tellg();
    stream.seekg(absoluteMcrfOffset);

    if (!stream)
    {
        log("[ERROR] Failed to seek to MCRF offset.", logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    ChunkHeader mcrfHeader;
    if (!readChunkHeader(stream, mcrfHeader))
    {
        log("[ERROR] Failed to read MCRF header.", logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    if (!compareChunkId(mcrfHeader.chunkId, MCRF_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MCRF ID mismatch.", logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    uint32_t expectedMcrfDataSize = (mcnkChunk.header.nDoodadRefs + mcnkChunk.header.nMapObjRefs) * sizeof(uint32_t);
    if (mcrfHeader.dataSize != expectedMcrfDataSize)
    {
        log("[ERROR] MCRF data size mismatch.", logMessages);
        stream.seekg(mcrfHeader.dataSize, std::ios::cur);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    if (expectedMcrfDataSize == 0)
    {
        log("[INFO] Found at offset 0x" + std::to_string(absoluteMcrfOffset) +
                ". Data size: 0. No references (nDoodadRefs=0, nMapObjRefs=0).",
            logMessages);
        stream.clear();
        stream.seekg(originalPos);
        mcnkChunk.hasMCRF = true;  // MCRF есть, но он пустой
        return true;
    }

    if (mcnkChunk.header.nDoodadRefs > 0)
    {
        mcnkChunk.mcrfData.doodadRefs.resize(mcnkChunk.header.nDoodadRefs);
        stream.read(reinterpret_cast<char*>(mcnkChunk.mcrfData.doodadRefs.data()),
                    mcnkChunk.header.nDoodadRefs * sizeof(uint32_t));
    }

    if (mcnkChunk.header.nMapObjRefs > 0)
    {
        mcnkChunk.mcrfData.mapObjectRefs.resize(mcnkChunk.header.nMapObjRefs);
        stream.read(reinterpret_cast<char*>(mcnkChunk.mcrfData.mapObjectRefs.data()),
                    mcnkChunk.header.nMapObjRefs * sizeof(uint32_t));
    }
    mcnkChunk.hasMCRF = true;
    log("MCRF: Parsed " + std::to_string(mcnkChunk.mcrfData.doodadRefs.size()) + " doodad refs and " +
            std::to_string(mcnkChunk.mcrfData.mapObjectRefs.size()) + " map object refs.",
        logMessages);

    stream.clear();
    stream.seekg(originalPos);
    return true;
}

bool Parser::parseMCVT(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset,
                       std::vector<std::string>& logMessages)
{
    if (mcnkChunk.header.ofsHeight == 0)
    {
        return true;  // Не ошибка, просто нет MCVT
    }

    // ofsHeight - это смещение от начала MCNK чанка.
    // Поток stream уже установлен на начало MCNK чанка.
    std::streampos originalPos = stream.tellg();
    stream.seekg(mcnkChunk.header.ofsHeight, std::ios::beg);  // Искать от начала MCNK

    if (!stream)
    {
        log("[ERROR] Failed to seek to MCVT offset.", logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    ChunkHeader mcvtHeader;
    if (!readChunkHeader(stream, mcvtHeader) || !compareChunkId(mcvtHeader.chunkId, "TVCM"))
    {
        log("[ERROR] MCVT header invalid.", logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    constexpr uint32_t expectedMcvtDataSize = 145 * sizeof(float);  // 580
    if (mcvtHeader.dataSize != expectedMcvtDataSize)
    {
        log("[ERROR] MCVT data size mismatch.", logMessages);
        stream.seekg(mcvtHeader.dataSize, std::ios::cur);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    stream.read(reinterpret_cast<char*>(mcnkChunk.mcvtData.heights.data()), expectedMcvtDataSize);
    if (!stream || stream.gcount() != expectedMcvtDataSize)
    {
        log("[ERROR] Failed to read MCVT heights data.", logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    mcnkChunk.hasMCVT = true;
    stream.clear();
    stream.seekg(originalPos);
    return true;
}

bool Parser::parseMCNR(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset,
                       std::vector<std::string>& logMessages)
{
    if (mcnkChunk.header.ofsNormal == 0)
    {
        return true;  // Нет MCNR
    }

    // ofsNormal - это смещение от начала MCNK чанка.
    // Поток stream уже установлен на начало MCNK чанка.
    std::streampos originalPos = stream.tellg();
    stream.seekg(mcnkChunk.header.ofsNormal, std::ios::beg);  // Искать от начала MCNK

    if (!stream)
    {
        log("[ERROR] Failed to seek to MCNR offset.", logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    ChunkHeader mcnrHeader;
    if (!readChunkHeader(stream, mcnrHeader) || !compareChunkId(mcnrHeader.chunkId, "RNCM"))
    {
        log("[ERROR] MCNR header invalid.", logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    constexpr uint32_t expectedMcnrDataSize = 145 * sizeof(MCNRData::Normal);  // 145 * 3 = 435
    if (mcnrHeader.dataSize != expectedMcnrDataSize)
    {
        log("[ERROR] MCNR data size mismatch.", logMessages);
        stream.seekg(mcnrHeader.dataSize, std::ios::cur);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    // Читаем нормали по одному байту, чтобы вручную переставить компоненты
    // из формата файла (ny, nz, nx) в стандартный (nx, ny, nz), как в python-скрипте.
    for (int i = 0; i < 145; ++i)
    {
        int8_t ny, nz, nx;
        stream.read(reinterpret_cast<char*>(&ny), 1);
        stream.read(reinterpret_cast<char*>(&nz), 1);
        stream.read(reinterpret_cast<char*>(&nx), 1);

        if (!stream)
        {
            log("[ERROR] Failed to read MCNR normals data block " + std::to_string(i), logMessages);
            stream.clear();
            stream.seekg(originalPos);
            return false;
        }

        mcnkChunk.mcnrData.normals[i] = {nx, ny, nz};
    }

    mcnkChunk.hasMCNR = true;
    stream.clear();
    stream.seekg(originalPos);
    return true;
}

bool Parser::parseMDDF(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    if (adtData.mhdr.offsetMDDF == 0)
    {
        log("[INFO] MHDR.offsetMDDF is 0. MDDF chunk will be skipped.", logMessages);
        return true;
    }

    stream.seekg(adtData.mhdr.offsetMDDF);
    if (!stream)
    {
        log("[ERROR] Failed to seek to MDDF chunk position (absolute offset): " +
                std::to_string(adtData.mhdr.offsetMDDF),
            logMessages);
        return false;
    }

    ChunkHeader mddfHeader;
    if (!readChunkHeader(stream, mddfHeader) || !compareChunkId(mddfHeader.chunkId, "FDDM"))
    {
        log("[ERROR] Invalid MDDF chunk header", logMessages);
        return false;
    }

    if (mddfHeader.dataSize % sizeof(SMDoodadDef) != 0)
    {
        log("[ERROR] MDDF data size is not a multiple of SMDoodadDef size. Size: " +
                std::to_string(mddfHeader.dataSize),
            logMessages);
        stream.seekg(mddfHeader.dataSize, std::ios::cur);
        return false;
    }

    size_t numDoodads = mddfHeader.dataSize / sizeof(SMDoodadDef);
    adtData.mddfDefs.resize(numDoodads);

    stream.read(reinterpret_cast<char*>(adtData.mddfDefs.data()), mddfHeader.dataSize);
    if (!stream || stream.gcount() != mddfHeader.dataSize)
    {
        log("[ERROR] Failed to read MDDF entries data.", logMessages);
        adtData.mddfDefs.clear();
        return false;
    }

    log("MDDF: Successfully parsed " + std::to_string(numDoodads) + " doodad definitions.", logMessages);
    return true;
}

bool Parser::parseMODF(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    if (adtData.mhdr.offsetMODF == 0)
    {
        log("[INFO] MHDR.offsetMODF is 0. MODF chunk will be skipped.", logMessages);
        return true;
    }

    stream.seekg(adtData.mhdr.offsetMODF);
    if (!stream)
    {
        log("[ERROR] Failed to seek to MODF chunk position (absolute offset): " +
                std::to_string(adtData.mhdr.offsetMODF),
            logMessages);
        return false;
    }

    ChunkHeader modfHeader;
    if (!readChunkHeader(stream, modfHeader) || !compareChunkId(modfHeader.chunkId, "FDOM"))
    {
        log("[ERROR] Invalid MODF chunk header", logMessages);
        return false;
    }

    if (modfHeader.dataSize % sizeof(SMMapObjDef) != 0)
    {
        log("[ERROR] MODF data size is not a multiple of SMMapObjDef size. Size: " +
                std::to_string(modfHeader.dataSize),
            logMessages);
        stream.seekg(modfHeader.dataSize, std::ios::cur);
        return false;
    }

    size_t numMapObjects = modfHeader.dataSize / sizeof(SMMapObjDef);
    adtData.modfDefs.resize(numMapObjects);

    stream.read(reinterpret_cast<char*>(adtData.modfDefs.data()), modfHeader.dataSize);
    if (!stream || stream.gcount() != modfHeader.dataSize)
    {
        log("[ERROR] Failed to read MODF entries data.", logMessages);
        adtData.modfDefs.clear();
        return false;
    }

    log("MODF: Successfully parsed " + std::to_string(numMapObjects) + " map object definitions.", logMessages);
    return true;
}

bool Parser::parseMMDX(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    if (adtData.mhdr.offsetMMDX == 0)
    {
        log("[INFO] MHDR.offsetMMDX is 0. MMDX chunk will be skipped.", logMessages);
        return true;
    }

    stream.seekg(adtData.mhdr.offsetMMDX);
    ChunkHeader header;
    if (!readChunkHeader(stream, header) || !compareChunkId(header.chunkId, "XDMM"))
    {
        log("[ERROR] Invalid MMDX chunk header", logMessages);
        return false;
    }

    adtData.mmdxData.resize(header.dataSize);
    stream.read(adtData.mmdxData.data(), header.dataSize);
    adtData.mmdxData.push_back('\0');  // Add a safety null terminator
    log("MMDX: Successfully parsed " + std::to_string(header.dataSize) + " bytes of model path data.", logMessages);
    return true;
}

bool Parser::parseMMID(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    if (adtData.mhdr.offsetMMID == 0)
    {
        log("[INFO] MHDR.offsetMMID is 0. MMID chunk will be skipped.", logMessages);
        return true;
    }

    stream.seekg(adtData.mhdr.offsetMMID);
    ChunkHeader header;
    if (!readChunkHeader(stream, header) || !compareChunkId(header.chunkId, "DIMM"))
    {
        log("[ERROR] Invalid MMID chunk header", logMessages);
        return false;
    }

    if (header.dataSize % sizeof(uint32_t) != 0)
    {
        log("[ERROR] MMID data size is not a multiple of 4.", logMessages);
        return false;
    }

    size_t numOffsets = header.dataSize / sizeof(uint32_t);
    adtData.mmidOffsets.resize(numOffsets);
    stream.read(reinterpret_cast<char*>(adtData.mmidOffsets.data()), header.dataSize);
    log("MMID: Successfully parsed " + std::to_string(numOffsets) + " model path offsets.", logMessages);
    return true;
}

bool Parser::parseMWMO(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    if (adtData.mhdr.offsetMWMO == 0)
    {
        log("[INFO] MHDR.offsetMWMO is 0. MWMO chunk will be skipped.", logMessages);
        return true;
    }

    stream.seekg(adtData.mhdr.offsetMWMO);
    ChunkHeader header;
    if (!readChunkHeader(stream, header) || !compareChunkId(header.chunkId, "OMWM"))
    {
        log("[ERROR] Invalid MWMO chunk header", logMessages);
        return false;
    }

    adtData.mwmoData.resize(header.dataSize);
    stream.read(adtData.mwmoData.data(), header.dataSize);
    adtData.mwmoData.push_back('\0');  // Add a safety null terminator
    log("MWMO: Successfully parsed " + std::to_string(header.dataSize) + " bytes of WMO path data.", logMessages);
    return true;
}

bool Parser::parseMWID(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    if (adtData.mhdr.offsetMWID == 0)
    {
        log("[INFO] MHDR.offsetMWID is 0. MWID chunk will be skipped.", logMessages);
        return true;
    }

    stream.seekg(adtData.mhdr.offsetMWID);
    ChunkHeader header;
    if (!readChunkHeader(stream, header) || !compareChunkId(header.chunkId, "DIWM"))
    {
        log("[ERROR] Invalid MWID chunk header", logMessages);
        return false;
    }

    if (header.dataSize % sizeof(uint32_t) != 0)
    {
        log("[ERROR] MWID data size is not a multiple of 4.", logMessages);
        return false;
    }

    size_t numOffsets = header.dataSize / sizeof(uint32_t);
    adtData.mwidOffsets.resize(numOffsets);
    stream.read(reinterpret_cast<char*>(adtData.mwidOffsets.data()), header.dataSize);
    log("MWID: Successfully parsed " + std::to_string(numOffsets) + " WMO path offsets.", logMessages);
    return true;
}

void Parser::resolveModelPaths(ADTData& adtData)
{
    auto extract_paths = [](const std::vector<char>& name_block, const std::vector<uint32_t>& offsets)
    {
        std::vector<std::string> paths;
        for (const auto& offset : offsets)
        {
            if (offset < name_block.size())
            {
                paths.emplace_back(&name_block[offset]);
            }
        }
        return paths;
    };

    adtData.doodadPaths = extract_paths(adtData.mmdxData, adtData.mmidOffsets);
    adtData.wmoPaths = extract_paths(adtData.mwmoData, adtData.mwidOffsets);
}

// Реализация parseMCNKs
bool Parser::parseMCNKs(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    log("--- Parsing " + std::to_string(adtData.mcinEntries.size()) + " MCNK chunks ---", logMessages);
    for (int i = 0; i < 256; ++i)
    {
        const auto& mcinEntry = adtData.mcinEntries[i];
        MCNKChunk& currentMcnk = adtData.mcnkChunks[i];  // Получаем ссылку на элемент массива

        currentMcnk.indexY = i / 16;
        currentMcnk.indexX = i % 16;

        if (mcinEntry.offset == 0 && mcinEntry.size == 0)
        {
            continue;
        }
        if (mcinEntry.offset == 0)
        {
            log("    MCNK [" + std::to_string(i) + "] (Y=" + std::to_string(currentMcnk.indexY) + ", X=" +
                    std::to_string(currentMcnk.indexX) + "): [WARNING] MCNK offset is 0 but size is not. Skipping.",
                logMessages);
            continue;
        }

        // Создаем под-поток для данных только этого MCNK чанка.
        // Это точно имитирует логику Python-скрипта.
        stream.seekg(mcinEntry.offset);
        std::vector<char> mcnkBuffer(mcinEntry.size);
        stream.read(mcnkBuffer.data(), mcinEntry.size);
        std::string mcnkDataStr(mcnkBuffer.begin(), mcnkBuffer.end());
        std::istringstream mcnkStream(mcnkDataStr, std::ios::binary);

        if (!mcnkStream)
        {
            log("    MCNK [" + std::to_string(i) +
                    "]: [ERROR] Failed to create istringstream for MCNK chunk at offset 0x" +
                    std::to_string(mcinEntry.offset),
                logMessages);
            continue;
        }

        ChunkHeader mcnkFileHeader;  // Это заголовок чанка MCNK (ID + размер данных MCNK)
        if (!readChunkHeader(mcnkStream, mcnkFileHeader))
        {
            log("    MCNK [" + std::to_string(i) + "]: [ERROR] Failed to read MCNK chunk header at offset 0x" +
                    std::to_string(mcinEntry.offset),
                logMessages);
            continue;
        }

        if (!compareChunkId(mcnkFileHeader.chunkId, MCNK_CHUNK_ID_REVERSED))
        {
            log("    MCNK [" + std::to_string(i) + "]: [ERROR] Expected ID 'MCNK' (KNCM), but found '" +
                    mcnkFileHeader.getReversedChunkIdStr() + "' at offset 0x" + std::to_string(mcinEntry.offset),
                logMessages);
            continue;
        }

        // Читаем 128-байтный заголовок данных MCNK
        if (!readChunkData(mcnkStream, sizeof(MCNKHeaderData), currentMcnk.header))
        {
            log("        MCNK [" + std::to_string(i) + "]: [ERROR] Failed to read 128-byte MCNK header data.",
                logMessages);
            continue;
        }

        // Проверка, что прочитанные indexX и indexY совпадают с вычисленными
        if (currentMcnk.header.indexX != currentMcnk.indexX || currentMcnk.header.indexY != currentMcnk.indexY)
        {
            log("        MCNK [" + std::to_string(i) +
                    "]: [WARNING] Index mismatch. Calculated YX: " + std::to_string(currentMcnk.indexY) + "," +
                    std::to_string(currentMcnk.indexX) + " vs Header YX: " + std::to_string(currentMcnk.header.indexY) +
                    "," + std::to_string(currentMcnk.header.indexX),
                logMessages);
        }

        // Парсим MCVT из под-потока
        if (!parseMCVT(mcnkStream, currentMcnk, mcinEntry.offset, logMessages))
        {
            // Ошибка уже залогирована в parseMCVT
        }

        // Парсим MCNR из под-потока
        if (!parseMCNR(mcnkStream, currentMcnk, mcinEntry.offset, logMessages))
        {
            // Ошибка уже залогирована в parseMCNR
        }

        // Парсим MCLQ (локальная жидкость), если нет глобальной MH2O
        if (!adtData.hasMH2O && currentMcnk.header.ofsMCLQ > 0)
        {
            if (!parseMCLQ(mcnkStream, currentMcnk, mcinEntry.offset, currentMcnk.header.sizeMCLQ, logMessages))
            {
                // Ошибка уже залогирована в parseMCLQ
            }
        }

        // Теперь парсим MCRF для этого MCNK
        // mcinEntry.offset - это абсолютное смещение начала MCNK чанка (его ID)
        if (currentMcnk.header.ofsRefs > 0 || currentMcnk.header.nDoodadRefs > 0 || currentMcnk.header.nMapObjRefs > 0)
        {
            if (!parseMCRF(mcnkStream, currentMcnk, mcinEntry.offset, logMessages))
            {
                // Ошибка уже залогирована в parseMCRF
            }
        }
    }
    return true;
}

bool Parser::parseMH2O(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    if (adtData.mhdr.offsetMH2O == 0)
    {
        log("[INFO] MHDR.offsetMH2O is 0. MH2O chunk will be skipped.", logMessages);
        adtData.hasMH2O = false;
        return true;
    }

    stream.seekg(adtData.mhdr.offsetMH2O);
    if (!stream)
    {
        log("[ERROR] Failed to seek to MH2O chunk position (absolute offset): " +
                std::to_string(adtData.mhdr.offsetMH2O),
            logMessages);
        return false;
    }

    const std::streampos mh2oBaseOffset = stream.tellg();

    ChunkHeader mh2oHeader;
    if (!readChunkHeader(stream, mh2oHeader) || !compareChunkId(mh2oHeader.chunkId, "O2HM"))
    {
        log("[ERROR] MH2O chunk header error.", logMessages);
        return false;
    }

    log("MH2O: Found chunk at offset " + std::to_string(adtData.mhdr.offsetMH2O) + " with data size " +
            std::to_string(mh2oHeader.dataSize),
        logMessages);

    // 1. Прочитать 256 SMLiquidChunk заголовков
    constexpr size_t liquidChunkHeadersSize = 256 * sizeof(SMLiquidChunk_WotLK);
    stream.read(reinterpret_cast<char*>(adtData.mh2oData.liquid_chunks.data()), liquidChunkHeadersSize);
    if (!stream || stream.gcount() != liquidChunkHeadersSize)
    {
        log("[ERROR] MH2O: Failed to read 256 SMLiquidChunk headers.", logMessages);
        return false;
    }

    // Здесь мы могли бы детально парсить instances, attributes, bitmaps и vertex data,
    // но для начала просто убедимся, что можем прочитать основные структуры, не вызывая падений.
    // Дальнейший детальный парсинг можно добавить при необходимости.
    // Пока что пропустим оставшуюся часть чанка, чтобы избежать ошибок.
    stream.seekg(mh2oBaseOffset);
    stream.seekg(sizeof(ChunkHeader) + mh2oHeader.dataSize, std::ios::cur);

    adtData.hasMH2O = true;
    log("MH2O: Successfully parsed 256 liquid chunk headers. Further detailed parsing is stubbed.", logMessages);
    return true;
}

bool Parser::parseMCLQ(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset, uint32_t sizeMCLQ,
                       std::vector<std::string>& logMessages)
{
    uint32_t absoluteMclqOffset = mcnkBaseOffset + mcnkChunk.header.ofsMCLQ;
    std::streampos originalPos = stream.tellg();
    stream.seekg(absoluteMclqOffset);

    if (!stream)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
                "] MCLQ: [ERROR] Failed to seek to MCLQ offset 0x" + std::to_string(absoluteMclqOffset),
            logMessages);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    // Поскольку точная структура MCLQ не определена в README,
    // мы просто логируем его наличие и размер, а затем пропускаем его данные.
    // Это предотвращает падение и позволяет продолжить парсинг.
    log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCLQ: Found local liquid chunk at offset 0x" + std::to_string(absoluteMclqOffset) + " with size " +
            std::to_string(sizeMCLQ) + ". Parsing is currently stubbed.",
        logMessages);

    stream.seekg(sizeMCLQ, std::ios::cur);

    mcnkChunk.hasMCLQ = true;
    stream.clear();
    stream.seekg(originalPos);
    return true;
}

bool Parser::parseInternal(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages)
{
    log("--- Analyzing ADT: " + adtData.adtSourceName + " ---", logMessages);

    if (!stream.good())
    {
        log("[CRITICAL ERROR] Stream is not in a good state before parsing: " + adtData.adtSourceName, logMessages);
        return false;
    }

    // 1. MVER
    if (!parseMVER(stream, adtData, logMessages))
    {
        log("  ADT " + adtData.adtSourceName + ": [CRITICAL] Problem with MVER chunk. Aborting.", logMessages);
        return false;
    }

    // 2. MHDR
    if (!parseMHDR(stream, adtData, logMessages))
    {
        log("  ADT " + adtData.adtSourceName + ": [CRITICAL] MHDR chunk not found or error after MVER. Aborting.",
            logMessages);
        return false;
    }

    // 3. Парсинг блоков данных о моделях и WMO. Это безопасно делать до MCNK,
    // так как они находятся в глобальной области видимости ADT и их смещения известны из MHDR.
    if (!parseMMDX(stream, adtData, logMessages))
        log("  ADT " + adtData.adtSourceName + ": [ERROR] Could not parse MMDX chunk.", logMessages);
    if (!parseMMID(stream, adtData, logMessages))
        log("  ADT " + adtData.adtSourceName + ": [ERROR] Could not parse MMID chunk.", logMessages);
    if (!parseMWMO(stream, adtData, logMessages))
        log("  ADT " + adtData.adtSourceName + ": [ERROR] Could not parse MWMO chunk.", logMessages);
    if (!parseMWID(stream, adtData, logMessages))
        log("  ADT " + adtData.adtSourceName + ": [ERROR] Could not parse MWID chunk.", logMessages);

    // После парсинга данных о моделях можно сразу разрешить пути
    resolveModelPaths(adtData);

    // 4. MDDF и MODF (определения Doodad и MapObject)
    if (!parseMDDF(stream, adtData, logMessages))
    {
        log("  ADT " + adtData.adtSourceName + ": [ERROR] Could not parse MDDF chunk.", logMessages);
    }
    if (!parseMODF(stream, adtData, logMessages))
    {
        log("  ADT " + adtData.adtSourceName + ": [ERROR] Could not parse MODF chunk.", logMessages);
    }

    // 5. MH2O (глобальная информация о воде)
    if (!parseMH2O(stream, adtData, logMessages))
    {
        log("  ADT " + adtData.adtSourceName + ": [ERROR] Could not parse MH2O chunk.", logMessages);
    }

    // 6. MCIN - содержит информацию о MCNK чанках, должен быть обработан до них.
    bool mcinParsedSuccessfully = false;
    if (adtData.mhdr.offsetMCIN > 0)
    {
        stream.seekg(adtData.mhdr.offsetMCIN);
        if (!stream)
        {
            log("  ADT " + adtData.adtSourceName +
                    ": [ERROR] Failed to seek to MCIN chunk position (absolute offset): " +
                    std::to_string(adtData.mhdr.offsetMCIN),
                logMessages);
        }
        else
        {
            if (parseMCIN(stream, adtData, logMessages))
            {
                mcinParsedSuccessfully = true;
            }
            else
            {
                log("  ADT " + adtData.adtSourceName + ": [ERROR] Could not parse MCIN chunk.", logMessages);
            }
        }
    }
    else
    {
        log("  ADT " + adtData.adtSourceName + ": [INFO] MHDR.offsetMCIN is 0, skipping MCIN and MCNK parsing.",
            logMessages);
    }

    // 7. MCNKs (и их дочерние чанки: MCRF, MCVT, MCNR и т.д.)
    if (mcinParsedSuccessfully)
    {
        if (!parseMCNKs(stream, adtData, logMessages))
        {
            log("  ADT " + adtData.adtSourceName + ": [ERROR] Errors during MCNK sub-chunks parsing.", logMessages);
        }
    }
    else
    {
        log("  ADT " + adtData.adtSourceName + ": MCNK analysis skipped as MCIN chunk was not read successfully.",
            logMessages);
    }

    return true;
}

std::optional<ADTData> Parser::parse(const std::vector<unsigned char>& dataBuffer, const std::string& adtNameForLogging)
{
    if (dataBuffer.empty())
    {
        qCWarning(log_adt_parser) << adtNameForLogging.c_str() << ": [ERROR] Input data buffer is empty.";
        return std::nullopt;
    }

    // Использование std::string как буфера для istringstream
    std::string dataStr(reinterpret_cast<const char*>(dataBuffer.data()), dataBuffer.size());
    std::istringstream stream(dataStr, std::ios::binary);

    if (!stream)
    {
        qCWarning(log_adt_parser) << adtNameForLogging.c_str()
                                  << ": [ERROR] Failed to create istringstream from data buffer.";
        return std::nullopt;
    }

    ADTData adtData;
    adtData.adtSourceName = adtNameForLogging;

    std::vector<std::string> logMessages;

    if (parseInternal(stream, adtData, logMessages))
    {
        return adtData;
    }

    qCWarning(log_adt_parser) << "ADT parsing failed for" << adtNameForLogging.c_str();
    for (const auto& msg : logMessages)
    {
        qCWarning(log_adt_parser) << "    " << msg.c_str();
    }

    return std::nullopt;
}

}  // namespace NavMeshTool::ADT
