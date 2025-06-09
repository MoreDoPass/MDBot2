#ifndef ADT_PARSER_H
#define ADT_PARSER_H

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <array>  // Для MCNK_Header_WotLK::reallyLowQualityTextureingMap и noEffectDoodad
#include <optional>

// Для C3Vector и CAaBox, если они будут определены в другом месте,
// нужно будет включить соответствующий заголовок.
// Пока определим их здесь упрощенно.
#pragma pack(push, 1)
struct C3Vector
{
    float x, y, z;
};

struct CAaBox
{
    C3Vector min_corner;
    C3Vector max_corner;
};
#pragma pack(pop)

namespace NavMeshTool::ADT
{
#pragma pack(push, 1)

// Общий заголовок чанка
struct ChunkHeader
{
    char chunkId[4];    // В файле ID хранится в обратном порядке (e.g., REVM для MVER)
    uint32_t dataSize;  // Размер данных чанка, не включая сам заголовок (ID + size)

    // Вспомогательная функция для получения ID в правильном порядке
    std::string getChunkIdStr() const
    {
        return std::string(chunkId, 4);
    }
    std::string getReversedChunkIdStr() const
    {
        char reversed[5] = {0};
        reversed[0] = chunkId[3];
        reversed[1] = chunkId[2];
        reversed[2] = chunkId[1];
        reversed[3] = chunkId[0];
        return std::string(reversed);
    }
};

// MVER чанк
constexpr char MVER_CHUNK_ID_REVERSED[] = "REVM";  // MVER
struct MVERData
{
    // ChunkHeader header; // Заголовок читается отдельно
    uint32_t version;  // Должна быть 18 для WotLK 3.3.5a
};

// MHDR чанк
constexpr char MHDR_CHUNK_ID_REVERSED[] = "RDHM";  // MHDR
struct MHDRData
{
    // ChunkHeader header; // Заголовок читается отдельно
    uint32_t flags;
    uint32_t offsetMCIN;
    uint32_t offsetMTEX;
    uint32_t offsetMMDX;
    uint32_t offsetMMID;
    uint32_t offsetMWMO;
    uint32_t offsetMWID;
    uint32_t offsetMDDF;
    uint32_t offsetMODF;
    uint32_t offsetMFBO;  // Если (flags & 0x1)
    uint32_t offsetMH2O;  // Если есть, иначе 0
    uint32_t offsetMTXF;  // Всегда 0 в WotLK
    uint8_t mamp_value;   // Всегда 0 в WotLK
    uint8_t padding[3];   // Всегда 00 00 00
    uint32_t unused[3];   // Всегда все нули
};  // Размер 64 байта

// Запись в MCIN чанке
constexpr char MCIN_CHUNK_ID_REVERSED[] = "NICM";  // MCIN
struct MCINEntry
{                      // 16 байт
    uint32_t offset;   // Смещение к данным MCNK чанка (от начала ADT файла)
    uint32_t size;     // Размер MCNK чанка
    uint32_t flags;    // В WotLK всегда 0
    uint32_t asyncId;  // В WotLK всегда 0
};  // 256 таких записей

// MDDF (doodad definitions)
constexpr char MDDF_CHUNK_ID_REVERSED[] = "FDDM";  // MDDF
struct SMDoodadDef
{
    uint32_t nameId;
    uint32_t uniqueId;
    C3Vector position;
    C3Vector rotation;
    uint16_t scale;
    uint16_t flags;
};  // 36 bytes

// MODF (map object definitions)
constexpr char MODF_CHUNK_ID_REVERSED[] = "FDOM";  // MODF
struct SMMapObjDef
{
    uint32_t nameId;
    uint32_t uniqueId;
    C3Vector position;
    C3Vector rotation;
    CAaBox extents;
    uint16_t flags;
    uint16_t doodadSet;
    uint16_t nameSet;
    uint16_t scale_or_padding;
};  // 64 bytes

// MMDX/MMID
constexpr char MMDX_CHUNK_ID_REVERSED[] = "XDMM";  // MMDX
constexpr char MMID_CHUNK_ID_REVERSED[] = "DIMM";  // MMID

// MWMO/MWID
constexpr char MWMO_CHUNK_ID_REVERSED[] = "OMWM";  // MWMO
constexpr char MWID_CHUNK_ID_REVERSED[] = "DIWM";  // MWID

// Заголовок MCNK чанка (128 байт)
constexpr char MCNK_CHUNK_ID_REVERSED[] = "KNCM";  // MCNK
struct MCNKHeaderData
{  // 128 байт
    uint32_t flags;
    uint32_t indexX;
    uint32_t indexY;
    uint32_t nLayers;
    uint32_t nDoodadRefs;
    uint32_t ofsHeight;  // MCVT
    uint32_t ofsNormal;  // MCNR
    uint32_t ofsLayer;   // MCLY
    uint32_t ofsRefs;    // MCRF
    uint32_t ofsAlpha;   // MCAL
    uint32_t sizeAlpha;
    uint32_t ofsShadow;  // MCSH (если flags.has_mcsh)
    uint32_t sizeShadow;
    uint32_t areaid;
    uint32_t nMapObjRefs;
    uint16_t holes_low_res;
    uint16_t unknown_padding_0x3E;  // или old_holes_high_res
    unsigned char reallyLowQualityTextureingMap[16];
    unsigned char noEffectDoodad[8];
    uint32_t ofsMCSE;
    uint32_t numMCSE;
    uint32_t ofsMCLQ;
    uint32_t sizeMCLQ;
    float zpos;
    float xpos;
    float ypos;
    uint32_t textureIdOrMCCV;  // Если MCCV есть, это поле часто 0
    uint32_t props;
    uint32_t effectId;
};

// MCRF чанк (ссылки на M2 и WMO)
constexpr char MCRF_CHUNK_ID_REVERSED[] = "FRCM";  // MCRF
// Данные MCRF - это просто массив uint32_t, их количество определяется nDoodadRefs и nMapObjRefs из MCNKHeaderData

// Список имен полей смещений в MHDR (для удобства, как в Python)
const std::vector<std::string> MHDR_OFFSET_FIELD_NAMES = {"MCIN", "MTEX", "MMDX", "MMID", "MWMO", "MWID",
                                                          "MDDF", "MODF", "MFBO", "MH2O", "MTXF"};

// --- Структуры для MH2O (Liquid Data) ---

// Заголовок для каждого из 256 MCNK чанков внутри MH2O
struct SMLiquidChunk_WotLK
{
    uint32_t offset_instances;   // Относительное смещение к SMLiquidInstance
    uint32_t layer_count;        // Количество слоев жидкости
    uint32_t offset_attributes;  // Относительное смещение к атрибутам
};

// Атрибуты жидкости для одного MCNK
struct mh2o_chunk_attributes
{
    uint64_t fishable;  // Битовая маска 8x8
    uint64_t deep;      // Битовая маска 8x8
};

// Один экземпляр (слой/прямоугольник) жидкости
struct SMLiquidInstance_WotLK
{
    uint16_t liquid_type;           // ID типа жидкости (ссылка на LiquidType.dbc)
    uint16_t LVF;                   // LiquidVertexFormat: формат данных вершин (0-3)
    float min_height_level;         // Мин. уровень высоты
    float max_height_level;         // Макс. уровень высоты
    uint8_t x_offset;               // Смещение по X (0-7)
    uint8_t y_offset;               // Смещение по Y (0-7)
    uint8_t width;                  // Ширина (1-8)
    uint8_t height;                 // Высота (1-8)
    uint32_t offset_exists_bitmap;  // Относительное смещение к битовой маске видимости
    uint32_t offset_vertex_data;    // Относительное смещение к данным вершин
};

// Структура для хранения всех данных MH2O
struct MH2OData
{
    std::array<SMLiquidChunk_WotLK, 256> liquid_chunks;
    std::vector<SMLiquidInstance_WotLK> instances;
    std::vector<mh2o_chunk_attributes> attributes;
    std::vector<unsigned char> vertex_data_buffer;  // Храним все данные вершин как сырой буфер
    std::vector<unsigned char> bitmap_data_buffer;  // Храним все битмапы как сырой буфер

    // Можно добавить методы для удобного доступа к данным, если потребуется
};

struct MCRFData
{
    std::vector<uint32_t> doodadRefs;
    std::vector<uint32_t> mapObjectRefs;
    bool hasMCRF = false;
    bool hasMCVT = false;
    bool hasMCNR = false;
};

struct MCVTData
{
    std::array<float, 145> heights;
};

struct MCNRData
{
    struct Normal
    {
        int8_t x, z, y;  // Порядок как в файле
    };
    std::array<Normal, 145> normals;
};

struct MCNKChunk
{
    uint32_t indexX = 0;
    uint32_t indexY = 0;
    MCNKHeaderData header{};
    MCRFData mcrfData;
    MCVTData mcvtData;
    MCNRData mcnrData;
    bool hasMCRF = false;
    bool hasMCVT = false;
    bool hasMCNR = false;
    bool hasMCLQ = false;  // Флаг для локальной жидкости
};

// Новая структура для хранения всех данных ADT
struct ADTData
{
    std::string adtSourceName;
    MVERData mver;
    MHDRData mhdr;
    std::array<MCINEntry, 256> mcinEntries;
    std::array<MCNKChunk, 256> mcnkChunks;
    std::vector<SMDoodadDef> mddfDefs;
    std::vector<SMMapObjDef> modfDefs;

    // Данные для имен моделей
    std::vector<char> mmdxData;
    std::vector<uint32_t> mmidOffsets;
    std::vector<char> mwmoData;
    std::vector<uint32_t> mwidOffsets;

    // Распарсенные и готовые к использованию пути
    std::vector<std::string> doodadPaths;
    std::vector<std::string> wmoPaths;

    MH2OData mh2oData;
    bool hasMH2O = false;
};

class Parser
{
   public:
    Parser() = default;
    ~Parser() = default;

    // Основной метод парсинга из буфера данных (например, от MpqManager)
    // Возвращает std::optional<ADTData>, содержащий все данные в случае успеха
    std::optional<ADTData> parse(const std::vector<unsigned char>& dataBuffer, const std::string& adtNameForLogging);

   private:
    // Внутренний метод, работающий с потоком и заполняющий структуру ADTData
    bool parseInternal(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);

    bool readChunkHeader(std::istream& stream, ChunkHeader& header);

    template <typename T>
    bool readChunkData(std::istream& stream, uint32_t dataSize, T& dataStruct);

    // Вспомогательные функции для парсинга конкретных чанков, принимающие istream
    bool parseMVER(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMHDR(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMCIN(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMCNKs(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMCRF(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset,
                   std::vector<std::string>& logMessages);
    bool parseMCVT(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset,
                   std::vector<std::string>& logMessages);
    bool parseMCNR(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset,
                   std::vector<std::string>& logMessages);
    bool parseMDDF(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMODF(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMMDX(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMMID(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMWMO(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMWID(std::istream& stream, ADTData& adtData, std::vector<std::string>& logMessages);
    bool parseMH2O(std::istream& stream, ADTData& adtData,
                   std::vector<std::string>& logMessages);  // Парсер для глобальной жидкости
    bool parseMCLQ(std::istream& stream, MCNKChunk& mcnkChunk, uint32_t mcnkBaseOffset, uint32_t sizeMCLQ,
                   std::vector<std::string>& logMessages);  // Парсер для локальной жидкости
    void resolveModelPaths(ADTData& adtData);

    // Другие приватные члены и методы, если понадобятся
    void log(const std::string& message, std::vector<std::string>& logMessages);
};

#pragma pack(pop)
}  // namespace NavMeshTool::ADT

#endif  // ADT_PARSER_H
