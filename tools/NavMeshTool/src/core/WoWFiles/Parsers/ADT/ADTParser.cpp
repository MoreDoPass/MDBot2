#include "ADTParser.h"
#include <iostream>  // Для std::cerr, std::cout
#include <vector>
#include <string_view>  // Для constexpr ID чанков
#include <algorithm>    // Для std::equal
#include <sstream>      // Для std::istringstream

namespace NavMeshTool::ADT
{

// Вспомогательная функция для сравнения ID чанков (char[4] с const char*)
// Не чувствительна к порядку байт в chunkIdFromFile, он должен быть как в файле (перевернут)
bool compareChunkId(const char chunkIdFromFile[4], const char* expectedReversedId)
{
    return chunkIdFromFile[0] == expectedReversedId[0] && chunkIdFromFile[1] == expectedReversedId[1] &&
           chunkIdFromFile[2] == expectedReversedId[2] && chunkIdFromFile[3] == expectedReversedId[3];
}

void Parser::log(const std::string& message)
{
    // Пока просто выводим в std::cout, в будущем можно интегрировать с QLoggingCategory
    // std::cout << message << std::endl;
    _logMessages.push_back(message);
}

bool Parser::readChunkHeader(std::istream& stream, ChunkHeader& header)
{
    stream.read(reinterpret_cast<char*>(&header), sizeof(ChunkHeader));
    if (!stream || stream.gcount() != sizeof(ChunkHeader))
    {
        log("[ERROR] Failed to read chunk header or EOF reached.");
        return false;
    }
    return true;
}

template <typename T>
bool Parser::readChunkData(std::istream& stream, uint32_t dataSize, T& dataStruct)
{
    if (dataSize != sizeof(T))
    {
        log("[ERROR] Data size mismatch for chunk. Expected " + std::to_string(sizeof(T)) + ", got " +
            std::to_string(dataSize) + " from header.");
        stream.seekg(dataSize, std::ios::cur);
        if (!stream)
        {
            log("[ERROR] Failed to seek past mismatched chunk data.");
            return false;
        }
        return false;
    }
    stream.read(reinterpret_cast<char*>(&dataStruct), sizeof(T));
    if (!stream || stream.gcount() != sizeof(T))
    {
        log("[ERROR] Failed to read chunk data for size " + std::to_string(sizeof(T)) + ".");
        return false;
    }
    return true;
}

// Реализация parseMVER
bool Parser::parseMVER(std::istream& stream)
{
    ChunkHeader mverHeader;
    if (!readChunkHeader(stream, mverHeader)) return false;

    if (!compareChunkId(mverHeader.chunkId, MVER_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MVER chunk ID mismatch. Found: " + std::string(mverHeader.chunkId, 4) +
            ", Expected: " + std::string(MVER_CHUNK_ID_REVERSED, 4));
        return false;
    }

    if (mverHeader.dataSize != sizeof(MVERData))
    {
        log("[ERROR] MVER data size mismatch. Expected " + std::to_string(sizeof(MVERData)) + ", got " +
            std::to_string(mverHeader.dataSize));
        stream.seekg(mverHeader.dataSize, std::ios::cur);  // Попытка пропустить данные
        return false;
    }

    if (!readChunkData(stream, mverHeader.dataSize, mver)) return false;

    if (mver.version != 18)
    {
        log("[WARNING] MVER version is not 18. Version: " + std::to_string(mver.version));
        // Продолжаем, но это может быть проблемой для WotLK.
    }
    log("MVER: Version " + std::to_string(mver.version) + " successfully parsed.");
    return true;
}

// Реализация parseMHDR
bool Parser::parseMHDR(std::istream& stream)
{
    ChunkHeader mhdrHeader;
    if (!readChunkHeader(stream, mhdrHeader)) return false;

    if (!compareChunkId(mhdrHeader.chunkId, MHDR_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MHDR chunk ID mismatch. Found: " + std::string(mhdrHeader.chunkId, 4) +
            ", Expected: " + std::string(MHDR_CHUNK_ID_REVERSED, 4));
        return false;
    }

    if (mhdrHeader.dataSize != sizeof(MHDRData))
    {
        log("[ERROR] MHDR data size mismatch. Expected " + std::to_string(sizeof(MHDRData)) + ", got " +
            std::to_string(mhdrHeader.dataSize));
        stream.seekg(mhdrHeader.dataSize, std::ios::cur);  // Попытка пропустить данные
        return false;
    }

    // Смещение MHDR данных от начала файла всегда 20 байт (12 MVER + 8 заголовок MHDR).
    constexpr uint32_t MVER_CHUNK_TOTAL_SIZE = 12;
    constexpr uint32_t MHDR_CHUNK_HEADER_SIZE = 8;
    constexpr uint32_t mhdrDataBlockStartOffset = MVER_CHUNK_TOTAL_SIZE + MHDR_CHUNK_HEADER_SIZE;  // 20

    if (!readChunkData(stream, mhdrHeader.dataSize, mhdr)) return false;

    // Корректируем смещения, чтобы они стали абсолютными (от начала файла).
    if (mhdr.offsetMCIN != 0) mhdr.offsetMCIN += mhdrDataBlockStartOffset;
    if (mhdr.offsetMTEX != 0) mhdr.offsetMTEX += mhdrDataBlockStartOffset;
    if (mhdr.offsetMMDX != 0) mhdr.offsetMMDX += mhdrDataBlockStartOffset;
    if (mhdr.offsetMMID != 0) mhdr.offsetMMID += mhdrDataBlockStartOffset;
    if (mhdr.offsetMWMO != 0) mhdr.offsetMWMO += mhdrDataBlockStartOffset;
    if (mhdr.offsetMWID != 0) mhdr.offsetMWID += mhdrDataBlockStartOffset;
    if (mhdr.offsetMDDF != 0) mhdr.offsetMDDF += mhdrDataBlockStartOffset;
    if (mhdr.offsetMODF != 0) mhdr.offsetMODF += mhdrDataBlockStartOffset;
    if (mhdr.offsetMFBO != 0) mhdr.offsetMFBO += mhdrDataBlockStartOffset;
    if (mhdr.offsetMH2O != 0) mhdr.offsetMH2O += mhdrDataBlockStartOffset;
    if (mhdr.offsetMTXF != 0) mhdr.offsetMTXF += mhdrDataBlockStartOffset;

    log("MHDR: Successfully parsed and offsets adjusted. Absolute OffsetMCIN: " + std::to_string(mhdr.offsetMCIN) +
        ", Absolute OffsetMTEX: " + std::to_string(mhdr.offsetMTEX));
    return true;
}

// Реализация parseMCIN
// mhdrDataBlockStartFileOffset - это абсолютное смещение в файле, где начинаются данные MHDR (после заголовка MHDR)
// В нашем случае MHDR всегда 64 байта, и его данные начинаются после MVER (12 байт) + заголовка MHDR (8 байт)
// т.е. 12 + 8 = 20 байт от начала файла.
bool Parser::parseMCIN(std::istream& stream)
{
    if (mhdr.offsetMCIN == 0)
    {
        log("[WARNING] MHDR.offsetMCIN is 0. MCIN chunk will be skipped.");
        return true;  // Не ошибка, просто нет MCIN
    }

    ChunkHeader mcinHeader;
    if (!readChunkHeader(stream, mcinHeader)) return false;

    if (!compareChunkId(mcinHeader.chunkId, MCIN_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MCIN chunk ID mismatch. ADT: " + adtSourceName + ". Found: " + std::string(mcinHeader.chunkId, 4) +
            ", Expected: " + std::string(MCIN_CHUNK_ID_REVERSED, 4));
        return false;
    }

    constexpr uint32_t expectedMcInDataSize = 256 * sizeof(MCINEntry);  // 256 * 16 = 4096
    if (mcinHeader.dataSize != expectedMcInDataSize)
    {
        log("[ERROR] MCIN data size mismatch. Expected " + std::to_string(expectedMcInDataSize) + ", got " +
            std::to_string(mcinHeader.dataSize));
        stream.seekg(mcinHeader.dataSize, std::ios::cur);
        return false;
    }

    stream.read(reinterpret_cast<char*>(mcinEntries.data()), expectedMcInDataSize);
    if (!stream || stream.gcount() != expectedMcInDataSize)
    {
        log("[ERROR] Failed to read MCIN entries data.");
        return false;
    }

    log("MCIN: Successfully parsed " + std::to_string(mcinEntries.size()) + " entries.");
    return true;
}

// Реализация parseMCRF
bool Parser::parseMCRF(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset)
{
    if (mcnkChunk.header.ofsRefs == 0)
    {
        // log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) + "] MCRF:
        // Offset 0, subchunk absent or not used (nDoodadRefs=" +
        //     std::to_string(mcnkChunk.header.nDoodadRefs) + ", nMapObjRefs=" +
        //     std::to_string(mcnkChunk.header.nMapObjRefs) + ").");
        if (mcnkChunk.header.nDoodadRefs == 0 && mcnkChunk.header.nMapObjRefs == 0)
        {
            // Нормальная ситуация
        }
        else
        {
            log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
                "] MCRF: [WARNING] MCRF Offset is 0, but nDoodadRefs=" + std::to_string(mcnkChunk.header.nDoodadRefs) +
                ", nMapObjRefs=" + std::to_string(mcnkChunk.header.nMapObjRefs) + ".");
        }
        return true;  // Не ошибка, просто нет MCRF
    }

    uint32_t absoluteMcrfOffset = mcnkBaseOffset + mcnkChunk.header.ofsRefs;
    std::streampos originalPos = stream.tellg();
    stream.seekg(absoluteMcrfOffset);

    if (!stream)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCRF: [ERROR] Failed to seek to MCRF offset 0x" +
            std::to_string(absoluteMcrfOffset));  // TODO: hex format
        stream.clear();                           // Clear error flags before seeking back
        stream.seekg(originalPos);
        return false;
    }

    ChunkHeader mcrfHeader;
    if (!readChunkHeader(stream, mcrfHeader))
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCRF: [ERROR] Failed to read MCRF header at offset 0x" + std::to_string(absoluteMcrfOffset));
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    if (!compareChunkId(mcrfHeader.chunkId, MCRF_CHUNK_ID_REVERSED))
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCRF: [ERROR] Expected ID 'MCRF' (FRCM), but found '" + mcrfHeader.getReversedChunkIdStr() +
            "' at offset 0x" + std::to_string(absoluteMcrfOffset));
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    uint32_t expectedMcrfDataSize = (mcnkChunk.header.nDoodadRefs + mcnkChunk.header.nMapObjRefs) * sizeof(uint32_t);
    if (mcrfHeader.dataSize != expectedMcrfDataSize)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCRF: [ERROR] Incorrect data size " + std::to_string(mcrfHeader.dataSize) + ". Expected " +
            std::to_string(expectedMcrfDataSize) +
            " bytes (based on nDoodadRefs=" + std::to_string(mcnkChunk.header.nDoodadRefs) +
            ", nMapObjRefs=" + std::to_string(mcnkChunk.header.nMapObjRefs) + ").");
        // Пропускаем данные, чтобы продолжить
        stream.seekg(mcrfHeader.dataSize, std::ios::cur);
        stream.clear();
        stream.seekg(originalPos);
        return false;  // Считаем ошибкой, если размер не совпадает
    }

    if (expectedMcrfDataSize == 0)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCRF: Found at offset 0x" + std::to_string(absoluteMcrfOffset) +
            ". Data size: 0. No references (nDoodadRefs=0, nMapObjRefs=0).");
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
        if (!stream || stream.gcount() != static_cast<std::streamsize>(mcnkChunk.header.nDoodadRefs * sizeof(uint32_t)))
        {
            log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
                "] MCRF: [ERROR] Failed to read doodad refs.");
            stream.clear();
            stream.seekg(originalPos);
            return false;
        }
        // log("        Doodad refs (" + std::to_string(mcnkChunk.header.nDoodadRefs) + "): ... "); // Добавить вывод,
        // если нужно
    }

    if (mcnkChunk.header.nMapObjRefs > 0)
    {
        mcnkChunk.mcrfData.mapObjectRefs.resize(mcnkChunk.header.nMapObjRefs);
        stream.read(reinterpret_cast<char*>(mcnkChunk.mcrfData.mapObjectRefs.data()),
                    mcnkChunk.header.nMapObjRefs * sizeof(uint32_t));
        if (!stream || stream.gcount() != static_cast<std::streamsize>(mcnkChunk.header.nMapObjRefs * sizeof(uint32_t)))
        {
            log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
                "] MCRF: [ERROR] Failed to read map object refs.");
            stream.clear();
            stream.seekg(originalPos);
            return false;
        }
        // log("        Map object refs (" + std::to_string(mcnkChunk.header.nMapObjRefs) + "): ... ");
    }
    mcnkChunk.hasMCRF = true;
    log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) + "] MCRF: Parsed " +
        std::to_string(mcnkChunk.mcrfData.doodadRefs.size()) + " doodad refs and " +
        std::to_string(mcnkChunk.mcrfData.mapObjectRefs.size()) + " map object refs.");

    stream.clear();
    stream.seekg(originalPos);
    return true;
}

bool Parser::parseMCVT(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset)
{
    if (mcnkChunk.header.ofsHeight == 0)
    {
        return true;  // Не ошибка, просто нет MCVT
    }

    uint32_t absoluteMcvtOffset = mcnkBaseOffset + mcnkChunk.header.ofsHeight;
    std::streampos originalPos = stream.tellg();
    stream.seekg(absoluteMcvtOffset);

    if (!stream)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCVT: [ERROR] Failed to seek to MCVT offset 0x" + std::to_string(absoluteMcvtOffset));
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    ChunkHeader mcvtHeader;
    if (!readChunkHeader(stream, mcvtHeader))
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCVT: [ERROR] Failed to read MCVT header at offset 0x" + std::to_string(absoluteMcvtOffset));
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    constexpr char MCVT_CHUNK_ID_REVERSED[] = "TVCM";
    if (!compareChunkId(mcvtHeader.chunkId, MCVT_CHUNK_ID_REVERSED))
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCVT: [ERROR] Expected ID 'MCVT' (TVCM), but found '" + mcvtHeader.getReversedChunkIdStr() +
            "' at offset 0x" + std::to_string(absoluteMcvtOffset));
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    constexpr uint32_t expectedMcvtDataSize = 145 * sizeof(float);  // 580
    if (mcvtHeader.dataSize != expectedMcvtDataSize)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCVT: [ERROR] Incorrect data size " + std::to_string(mcvtHeader.dataSize) + ". Expected " +
            std::to_string(expectedMcvtDataSize) + " bytes.");
        stream.seekg(mcvtHeader.dataSize, std::ios::cur);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    stream.read(reinterpret_cast<char*>(mcnkChunk.mcvtData.heights.data()), expectedMcvtDataSize);
    if (!stream || stream.gcount() != expectedMcvtDataSize)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCVT: [ERROR] Failed to read MCVT heights data.");
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    mcnkChunk.hasMCVT = true;
    stream.clear();
    stream.seekg(originalPos);
    return true;
}

bool Parser::parseMCNR(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset)
{
    if (mcnkChunk.header.ofsNormal == 0)
    {
        return true;  // Нет MCNR
    }

    uint32_t absoluteMcnrOffset = mcnkBaseOffset + mcnkChunk.header.ofsNormal;
    std::streampos originalPos = stream.tellg();
    stream.seekg(absoluteMcnrOffset);

    if (!stream)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCNR: [ERROR] Failed to seek to MCNR offset 0x" + std::to_string(absoluteMcnrOffset));
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    ChunkHeader mcnrHeader;
    if (!readChunkHeader(stream, mcnrHeader))
    {
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    constexpr char MCNR_CHUNK_ID_REVERSED[] = "RNCM";
    if (!compareChunkId(mcnrHeader.chunkId, MCNR_CHUNK_ID_REVERSED))
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCNR: [ERROR] Expected ID 'MCNR' (RNCM), but found '" + mcnrHeader.getReversedChunkIdStr() +
            "' at offset 0x" + std::to_string(absoluteMcnrOffset));
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    constexpr uint32_t expectedMcnrDataSize = 145 * sizeof(MCNRData::Normal);  // 145 * 3 = 435
    if (mcnrHeader.dataSize != expectedMcnrDataSize)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCNR: [ERROR] Incorrect data size " + std::to_string(mcnrHeader.dataSize) + ". Expected " +
            std::to_string(expectedMcnrDataSize) + " bytes.");
        stream.seekg(mcnrHeader.dataSize, std::ios::cur);
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    stream.read(reinterpret_cast<char*>(mcnkChunk.mcnrData.normals.data()), expectedMcnrDataSize);
    if (!stream || stream.gcount() != expectedMcnrDataSize)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCNR: [ERROR] Failed to read MCNR normals data.");
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    mcnkChunk.hasMCNR = true;
    stream.clear();
    stream.seekg(originalPos);
    return true;
}

bool Parser::parseMDDF(std::istream& stream)
{
    if (mhdr.offsetMDDF == 0)
    {
        log("[INFO] MHDR.offsetMDDF is 0. MDDF chunk will be skipped.");
        return true;
    }

    stream.seekg(mhdr.offsetMDDF);
    if (!stream)
    {
        log("[ERROR] Failed to seek to MDDF chunk position (absolute offset): " + std::to_string(mhdr.offsetMDDF));
        return false;
    }

    ChunkHeader mddfHeader;
    if (!readChunkHeader(stream, mddfHeader)) return false;

    if (!compareChunkId(mddfHeader.chunkId, MDDF_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MDDF chunk ID mismatch. Found: " + std::string(mddfHeader.chunkId, 4) +
            ", Expected: " + std::string(MDDF_CHUNK_ID_REVERSED, 4));
        return false;
    }

    if (mddfHeader.dataSize % sizeof(SMDoodadDef) != 0)
    {
        log("[ERROR] MDDF data size is not a multiple of SMDoodadDef size. Size: " +
            std::to_string(mddfHeader.dataSize));
        stream.seekg(mddfHeader.dataSize, std::ios::cur);
        return false;
    }

    size_t numDoodads = mddfHeader.dataSize / sizeof(SMDoodadDef);
    mddfDefs.resize(numDoodads);

    stream.read(reinterpret_cast<char*>(mddfDefs.data()), mddfHeader.dataSize);
    if (!stream || stream.gcount() != mddfHeader.dataSize)
    {
        log("[ERROR] Failed to read MDDF entries data.");
        mddfDefs.clear();
        return false;
    }

    log("MDDF: Successfully parsed " + std::to_string(numDoodads) + " doodad definitions.");
    return true;
}

bool Parser::parseMODF(std::istream& stream)
{
    if (mhdr.offsetMODF == 0)
    {
        log("[INFO] MHDR.offsetMODF is 0. MODF chunk will be skipped.");
        return true;
    }

    stream.seekg(mhdr.offsetMODF);
    if (!stream)
    {
        log("[ERROR] Failed to seek to MODF chunk position (absolute offset): " + std::to_string(mhdr.offsetMODF));
        return false;
    }

    ChunkHeader modfHeader;
    if (!readChunkHeader(stream, modfHeader)) return false;

    if (!compareChunkId(modfHeader.chunkId, MODF_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MODF chunk ID mismatch. Found: " + std::string(modfHeader.chunkId, 4) +
            ", Expected: " + std::string(MODF_CHUNK_ID_REVERSED, 4));
        return false;
    }

    if (modfHeader.dataSize % sizeof(SMMapObjDef) != 0)
    {
        log("[ERROR] MODF data size is not a multiple of SMMapObjDef size. Size: " +
            std::to_string(modfHeader.dataSize));
        stream.seekg(modfHeader.dataSize, std::ios::cur);
        return false;
    }

    size_t numMapObjects = modfHeader.dataSize / sizeof(SMMapObjDef);
    modfDefs.resize(numMapObjects);

    stream.read(reinterpret_cast<char*>(modfDefs.data()), modfHeader.dataSize);
    if (!stream || stream.gcount() != modfHeader.dataSize)
    {
        log("[ERROR] Failed to read MODF entries data.");
        modfDefs.clear();
        return false;
    }

    log("MODF: Successfully parsed " + std::to_string(numMapObjects) + " map object definitions.");
    return true;
}

bool Parser::parseMH2O(std::istream& stream)
{
    if (mhdr.offsetMH2O == 0)
    {
        log("[INFO] MHDR.offsetMH2O is 0. MH2O chunk will be skipped.");
        hasMH2O = false;
        return true;
    }

    stream.seekg(mhdr.offsetMH2O);
    if (!stream)
    {
        log("[ERROR] Failed to seek to MH2O chunk position (absolute offset): " + std::to_string(mhdr.offsetMH2O));
        return false;
    }

    const std::streampos mh2oBaseOffset = stream.tellg();

    ChunkHeader mh2oHeader;
    if (!readChunkHeader(stream, mh2oHeader) || !compareChunkId(mh2oHeader.chunkId, "O2HM"))
    {
        log("[ERROR] MH2O chunk header error.");
        return false;
    }

    log("MH2O: Found chunk at offset " + std::to_string(mhdr.offsetMH2O) + " with data size " +
        std::to_string(mh2oHeader.dataSize));

    // 1. Прочитать 256 SMLiquidChunk заголовков
    constexpr size_t liquidChunkHeadersSize = 256 * sizeof(SMLiquidChunk_WotLK);
    stream.read(reinterpret_cast<char*>(mh2oData.liquid_chunks.data()), liquidChunkHeadersSize);
    if (!stream || stream.gcount() != liquidChunkHeadersSize)
    {
        log("[ERROR] MH2O: Failed to read 256 SMLiquidChunk headers.");
        return false;
    }

    // Здесь мы могли бы детально парсить instances, attributes, bitmaps и vertex data,
    // но для начала просто убедимся, что можем прочитать основные структуры, не вызывая падений.
    // Дальнейший детальный парсинг можно добавить при необходимости.
    // Пока что пропустим оставшуюся часть чанка, чтобы избежать ошибок.
    stream.seekg(mh2oBaseOffset);
    stream.seekg(sizeof(ChunkHeader) + mh2oHeader.dataSize, std::ios::cur);

    hasMH2O = true;
    log("MH2O: Successfully parsed 256 liquid chunk headers. Further detailed parsing is stubbed.");
    return true;
}

bool Parser::parseMMDX(std::istream& stream)
{
    if (mhdr.offsetMMDX == 0)
    {
        log("[INFO] MHDR.offsetMMDX is 0. MMDX chunk will be skipped.");
        return true;
    }

    stream.seekg(mhdr.offsetMMDX);
    ChunkHeader header;
    if (!readChunkHeader(stream, header) || !compareChunkId(header.chunkId, MMDX_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MMDX chunk header error.");
        return false;
    }

    mmdxData.resize(header.dataSize);
    stream.read(mmdxData.data(), header.dataSize);
    mmdxData.push_back('\\0');  // Add a safety null terminator
    log("MMDX: Successfully parsed " + std::to_string(header.dataSize) + " bytes of model path data.");
    return true;
}

bool Parser::parseMMID(std::istream& stream)
{
    if (mhdr.offsetMMID == 0)
    {
        log("[INFO] MHDR.offsetMMID is 0. MMID chunk will be skipped.");
        return true;
    }

    stream.seekg(mhdr.offsetMMID);
    ChunkHeader header;
    if (!readChunkHeader(stream, header) || !compareChunkId(header.chunkId, MMID_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MMID chunk header error.");
        return false;
    }

    if (header.dataSize % sizeof(uint32_t) != 0)
    {
        log("[ERROR] MMID data size is not a multiple of 4.");
        return false;
    }

    size_t numOffsets = header.dataSize / sizeof(uint32_t);
    mmidOffsets.resize(numOffsets);
    stream.read(reinterpret_cast<char*>(mmidOffsets.data()), header.dataSize);
    log("MMID: Successfully parsed " + std::to_string(numOffsets) + " model path offsets.");
    return true;
}

bool Parser::parseMWMO(std::istream& stream)
{
    if (mhdr.offsetMWMO == 0)
    {
        log("[INFO] MHDR.offsetMWMO is 0. MWMO chunk will be skipped.");
        return true;
    }

    stream.seekg(mhdr.offsetMWMO);
    ChunkHeader header;
    if (!readChunkHeader(stream, header) || !compareChunkId(header.chunkId, MWMO_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MWMO chunk header error.");
        return false;
    }

    mwmoData.resize(header.dataSize);
    stream.read(mwmoData.data(), header.dataSize);
    mwmoData.push_back('\\0');  // Add a safety null terminator
    log("MWMO: Successfully parsed " + std::to_string(header.dataSize) + " bytes of WMO path data.");
    return true;
}

bool Parser::parseMWID(std::istream& stream)
{
    if (mhdr.offsetMWID == 0)
    {
        log("[INFO] MHDR.offsetMWID is 0. MWID chunk will be skipped.");
        return true;
    }

    stream.seekg(mhdr.offsetMWID);
    ChunkHeader header;
    if (!readChunkHeader(stream, header) || !compareChunkId(header.chunkId, MWID_CHUNK_ID_REVERSED))
    {
        log("[ERROR] MWID chunk header error.");
        return false;
    }

    if (header.dataSize % sizeof(uint32_t) != 0)
    {
        log("[ERROR] MWID data size is not a multiple of 4.");
        return false;
    }

    size_t numOffsets = header.dataSize / sizeof(uint32_t);
    mwidOffsets.resize(numOffsets);
    stream.read(reinterpret_cast<char*>(mwidOffsets.data()), header.dataSize);
    log("MWID: Successfully parsed " + std::to_string(numOffsets) + " WMO path offsets.");
    return true;
}

void Parser::resolveModelPaths()
{
    // Resolve Doodad (M2) paths
    if (!mmidOffsets.empty() && !mmdxData.empty())
    {
        doodadPaths.reserve(mmidOffsets.size());
        for (uint32_t offset : mmidOffsets)
        {
            if (offset < mmdxData.size())
            {
                doodadPaths.emplace_back(&mmdxData[offset]);
            }
            else
            {
                log("[WARNING] Invalid offset in MMID: " + std::to_string(offset));
                doodadPaths.emplace_back("INVALID_PATH");
            }
        }
        log("Resolved " + std::to_string(doodadPaths.size()) + " doodad paths.");
    }

    // Resolve WMO paths
    if (!mwidOffsets.empty() && !mwmoData.empty())
    {
        wmoPaths.reserve(mwidOffsets.size());
        for (uint32_t offset : mwidOffsets)
        {
            if (offset < mwmoData.size())
            {
                wmoPaths.emplace_back(&mwmoData[offset]);
            }
            else
            {
                log("[WARNING] Invalid offset in MWID: " + std::to_string(offset));
                wmoPaths.emplace_back("INVALID_PATH");
            }
        }
        log("Resolved " + std::to_string(wmoPaths.size()) + " WMO paths.");
    }
}

// Реализация parseMCNKs
bool Parser::parseMCNKs(std::istream& stream)
{
    log("--- Parsing " + std::to_string(mcinEntries.size()) + " MCNK chunks ---");
    for (int i = 0; i < 256; ++i)
    {
        const auto& mcinEntry = mcinEntries[i];
        MCNKChunk& currentMcnk = mcnkChunks[i];  // Получаем ссылку на элемент массива

        currentMcnk.indexY = i / 16;
        currentMcnk.indexX = i % 16;

        if (mcinEntry.offset == 0 && mcinEntry.size == 0)
        {
            // log("    MCNK [" + std::to_string(i) + "] (Y=" + std::to_string(currentMcnk.indexY) + ", X=" +
            // std::to_string(currentMcnk.indexX) + "): Offset and Size are 0. Skipping.");
            continue;
        }
        if (mcinEntry.offset == 0)
        {
            log("    MCNK [" + std::to_string(i) + "] (Y=" + std::to_string(currentMcnk.indexY) + ", X=" +
                std::to_string(currentMcnk.indexX) + "): [WARNING] MCNK offset is 0 but size is not. Skipping.");
            continue;
        }

        std::streampos originalPos = stream.tellg();
        stream.seekg(mcinEntry.offset);
        if (!stream)
        {
            log("    MCNK [" + std::to_string(i) + "]: [ERROR] Failed to seek to MCNK offset 0x" +
                std::to_string(mcinEntry.offset));
            stream.clear();
            stream.seekg(originalPos);  // Вернуть курсор
            continue;
        }

        ChunkHeader mcnkFileHeader;  // Это заголовок чанка MCNK (ID + размер данных MCNK)
        if (!readChunkHeader(stream, mcnkFileHeader))
        {
            log("    MCNK [" + std::to_string(i) + "]: [ERROR] Failed to read MCNK chunk header at offset 0x" +
                std::to_string(mcinEntry.offset));
            stream.clear();
            stream.seekg(originalPos);
            continue;
        }

        if (!compareChunkId(mcnkFileHeader.chunkId, MCNK_CHUNK_ID_REVERSED))
        {
            log("    MCNK [" + std::to_string(i) + "]: [ERROR] Expected ID 'MCNK' (KNCM), but found '" +
                mcnkFileHeader.getReversedChunkIdStr() + "' at offset 0x" + std::to_string(mcinEntry.offset));
            stream.clear();
            stream.seekg(originalPos);
            continue;
        }

        // mcnkFileHeader.dataSize должен быть равен mcinEntry.size - 8 (размер заголовка самого чанка)
        // if (mcnkFileHeader.dataSize != (mcinEntry.size - sizeof(ChunkHeader))) {
        //     log("    MCNK [" + std::to_string(i) + "]: [WARNING] MCNK data size from its header (" +
        //     std::to_string(mcnkFileHeader.dataSize) +
        //         ") does not match MCIN entry size minus header_size (" + std::to_string(mcinEntry.size -
        //         sizeof(ChunkHeader)) + "). Using MCIN size for safety.");
        // }

        // Читаем 128-байтный заголовок данных MCNK
        if (!readChunkData(stream, sizeof(MCNKHeaderData), currentMcnk.header))
        {
            log("        MCNK [" + std::to_string(i) + "]: [ERROR] Failed to read 128-byte MCNK header data.");
            stream.clear();
            stream.seekg(originalPos);
            continue;
        }

        // Проверка, что прочитанные indexX и indexY совпадают с вычисленными
        if (currentMcnk.header.indexX != currentMcnk.indexX || currentMcnk.header.indexY != currentMcnk.indexY)
        {
            log("        MCNK [" + std::to_string(i) +
                "]: [WARNING] Index mismatch. Calculated YX: " + std::to_string(currentMcnk.indexY) + "," +
                std::to_string(currentMcnk.indexX) + " vs Header YX: " + std::to_string(currentMcnk.header.indexY) +
                "," + std::to_string(currentMcnk.header.indexX));
        }

        // Парсим MCVT
        if (!parseMCVT(stream, currentMcnk, mcinEntry.offset))
        {
            // Ошибка уже залогирована в parseMCVT
        }

        // Парсим MCNR
        if (!parseMCNR(stream, currentMcnk, mcinEntry.offset))
        {
            // Ошибка уже залогирована в parseMCNR
        }

        // Парсим MCLQ (локальная жидкость), если нет глобальной MH2O
        if (!hasMH2O && currentMcnk.header.ofsMCLQ > 0)
        {
            if (!parseMCLQ(stream, currentMcnk, mcinEntry.offset, currentMcnk.header.sizeMCLQ))
            {
                // Ошибка уже залогирована в parseMCLQ
            }
        }

        // Теперь парсим MCRF для этого MCNK
        // mcinEntry.offset - это абсолютное смещение начала MCNK чанка (его ID)
        if (currentMcnk.header.ofsRefs > 0 || currentMcnk.header.nDoodadRefs > 0 || currentMcnk.header.nMapObjRefs > 0)
        {
            if (!parseMCRF(stream, currentMcnk, mcinEntry.offset))
            {
                // Ошибка уже залогирована в parseMCRF
            }
        }

        stream.clear();
        stream.seekg(originalPos);  // Восстанавливаем позицию для следующего MCNK или другого чанка
    }
    return true;
}

// Внутренний метод parseInternal (бывший parseFromStream)
bool Parser::parseInternal(std::istream& stream, const std::string& sourceNameForLogging)
{
    adtSourceName = sourceNameForLogging;
    _logMessages.clear();
    log("--- Analyzing ADT: " + sourceNameForLogging + " ---");

    if (!stream.good())
    {
        log("[CRITICAL ERROR] Stream is not in a good state before parsing: " + sourceNameForLogging);
        return false;
    }

    // 1. MVER
    if (!parseMVER(stream))
    {
        log("  ADT " + sourceNameForLogging + ": [CRITICAL] Problem with MVER chunk. Aborting.");
        return false;
    }

    // 2. MHDR
    if (!parseMHDR(stream))
    {
        log("  ADT " + sourceNameForLogging + ": [CRITICAL] MHDR chunk not found or error after MVER. Aborting.");
        return false;
    }

    // 3. Парсинг блоков данных о моделях и WMO. Это безопасно делать до MCNK,
    // так как они находятся в глобальной области видимости ADT и их смещения известны из MHDR.
    if (!parseMMDX(stream)) log("  ADT " + sourceNameForLogging + ": [ERROR] Could not parse MMDX chunk.");
    if (!parseMMID(stream)) log("  ADT " + sourceNameForLogging + ": [ERROR] Could not parse MMID chunk.");
    if (!parseMWMO(stream)) log("  ADT " + sourceNameForLogging + ": [ERROR] Could not parse MWMO chunk.");
    if (!parseMWID(stream)) log("  ADT " + sourceNameForLogging + ": [ERROR] Could not parse MWID chunk.");

    // После парсинга данных о моделях можно сразу разрешить пути
    resolveModelPaths();

    // 4. MDDF и MODF (определения Doodad и MapObject)
    if (!parseMDDF(stream))
    {
        log("  ADT " + sourceNameForLogging + ": [ERROR] Could not parse MDDF chunk.");
    }
    if (!parseMODF(stream))
    {
        log("  ADT " + sourceNameForLogging + ": [ERROR] Could not parse MODF chunk.");
    }

    // 5. MH2O (глобальная информация о воде)
    if (!parseMH2O(stream))
    {
        log("  ADT " + sourceNameForLogging + ": [ERROR] Could not parse MH2O chunk.");
    }

    // 6. MCIN - содержит информацию о MCNK чанках, должен быть обработан до них.
    bool mcinParsedSuccessfully = false;
    if (mhdr.offsetMCIN > 0)
    {
        stream.seekg(mhdr.offsetMCIN);
        if (!stream)
        {
            log("  ADT " + sourceNameForLogging +
                ": [ERROR] Failed to seek to MCIN chunk position (absolute offset): " +
                std::to_string(mhdr.offsetMCIN));
        }
        else
        {
            if (parseMCIN(stream))
            {
                mcinParsedSuccessfully = true;
            }
            else
            {
                log("  ADT " + sourceNameForLogging + ": [ERROR] Could not parse MCIN chunk.");
            }
        }
    }
    else
    {
        log("  ADT " + sourceNameForLogging + ": [INFO] MHDR.offsetMCIN is 0, skipping MCIN and MCNK parsing.");
    }

    // 7. MCNKs (и их дочерние чанки: MCRF, MCVT, MCNR и т.д.)
    if (mcinParsedSuccessfully)
    {
        if (!parseMCNKs(stream))
        {
            log("  ADT " + sourceNameForLogging + ": [ERROR] Errors during MCNK sub-chunks parsing.");
        }
    }
    else
    {
        log("  ADT " + sourceNameForLogging + ": MCNK analysis skipped as MCIN chunk was not read successfully.");
    }

    // Вывод всех накопленных логов в консоль
    for (const auto& msg : _logMessages)
    {
        std::cout << msg << std::endl;
    }

    log("--- Analysis finished for: " + sourceNameForLogging + " ---");
    return true;
}

// Новый метод parse из буфера
bool Parser::parse(const std::vector<unsigned char>& dataBuffer, const std::string& adtNameForLogging)
{
    if (dataBuffer.empty())
    {
        _logMessages.clear();
        log("[CRITICAL ERROR] Data buffer is empty for ADT: " + adtNameForLogging);
        for (const auto& msg : _logMessages)
        {
            std::cout << msg << std::endl;
        }
        return false;
    }
    // Создаем istringstream из данных вектора
    // Важно: reinterpret_cast<const char*> безопасен, т.к. unsigned char и char одного размера
    // и стандарт гарантирует возможность такого преобразования для доступа к объектному представлению.
    std::istringstream stream(std::string(reinterpret_cast<const char*>(dataBuffer.data()), dataBuffer.size()),
                              std::ios::binary);
    return parseInternal(stream, adtNameForLogging);
}

bool Parser::parseMCLQ(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset, uint32_t sizeMCLQ)
{
    uint32_t absoluteMclqOffset = mcnkBaseOffset + mcnkChunk.header.ofsMCLQ;
    std::streampos originalPos = stream.tellg();
    stream.seekg(absoluteMclqOffset);

    if (!stream)
    {
        log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
            "] MCLQ: [ERROR] Failed to seek to MCLQ offset 0x" + std::to_string(absoluteMclqOffset));
        stream.clear();
        stream.seekg(originalPos);
        return false;
    }

    // Поскольку точная структура MCLQ не определена в README,
    // мы просто логируем его наличие и размер, а затем пропускаем его данные.
    // Это предотвращает падение и позволяет продолжить парсинг.
    log("      MCNK[" + std::to_string(mcnkChunk.indexY) + "," + std::to_string(mcnkChunk.indexX) +
        "] MCLQ: Found local liquid chunk at offset 0x" + std::to_string(absoluteMclqOffset) + " with size " +
        std::to_string(sizeMCLQ) + ". Parsing is currently stubbed.");

    stream.seekg(sizeMCLQ, std::ios::cur);

    mcnkChunk.hasMCLQ = true;
    stream.clear();
    stream.seekg(originalPos);
    return true;
}

}  // namespace NavMeshTool::ADT
