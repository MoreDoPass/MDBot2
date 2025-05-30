#pragma once

#include <string>
#include <vector>
#include <cstdint>  // Для uint32_t, uint16_t и т.д.

#include <QLoggingCategory>  // Добавляем для логирования Qt

// Объявляем категорию логирования для WDT парсера
Q_DECLARE_LOGGING_CATEGORY(logWdtParser)

namespace NavMeshTool
{
namespace WDT
{

// --- Структуры данных из WDT файла ---

/**
 * @brief Структура для чанка MPHD (Map Header).
 */
struct MPHDChunk
{
    uint32_t flags;
    uint32_t
        wdtEntryId;  // В старых версиях это могло быть что-то другое (например, something из wowdev)
                     // Для 3.3.5a wowdev упоминает "something" которое делится на 8, но также и mapID.
                     // Это поле требует более детального изучения для 3.3.5a, пока оставим как wdtEntryId/something.
    uint32_t unused[6];  // Остальные поля, которые могут быть неиспользуемыми или зарезервированными в 3.3.5a
};

/**
 * @brief Структура для одной записи в чанке MAIN (Map Area Information).
 */
struct SMAreaInfo
{
    uint32_t flags;    // Поле флагов (например, has_adt_file)
    uint32_t asyncId;  // Используется клиентом во время выполнения, для парсинга обычно не критично
};

// Флаги для SMAreaInfo.flags (основываясь на wowdev и общих знаниях)
constexpr uint32_t SMAREA_FLAG_HAS_ADT = 0x1;  // Указывает на наличие ADT файла для этого тайла

/**
 * @brief Структура для одной записи в чанке MODF (Map Object Definition Flags).
 */
struct MODFEntry
{
    uint32_t nameId;    // Смещение имени файла WMO в чанке MWMO или ID в зависимости от версии. Для 3.3.5a это скорее
                        // смещение.
    uint32_t uniqueId;  // Уникальный ID для этого экземпляра объекта
    float position[3];  // X, Y, Z координаты
    float orientation[3];  // Поворот в градусах по осям X, Y, Z
    float extents[6];      // AABB (minX, minY, minZ, maxX, maxY, maxZ)
    uint16_t flags;        // Флаги объекта (например, использовать ли extents)
    uint16_t doodadSet;    // Индекс набора MMDX/MMDD (декораций)
    uint32_t nameSet;      // Имя набора, обычно 0
    uint32_t scale;        // В 3.3.5a это поле может быть частью структуры, но не использоваться как scale.
                           // Wowdev: "new in BFA... Needs to be 1024 for no scaling."
                           // Для 3.3.5a это, вероятно, 0 или неинтерпретируемые данные в этом месте.
};

// Флаги для MODFEntry.flags
constexpr uint16_t MODF_FLAG_USE_EXTENTS = 0x1;  // Использовать геометрию из extents (для коллизий и т.п.)
// Другие флаги могут быть здесь, если известны

/**
 * @brief Структура для хранения всех данных, извлеченных из WDT файла.
 */
struct WDTData
{
    uint32_t version = 0;  // Из чанка MVER
    MPHDChunk mphd{};
    std::vector<SMAreaInfo> mainEntries;     // 64*64 = 4096 записей
    std::vector<std::string> mwmoFilenames;  // Имена файлов из чанка MWMO
    std::vector<MODFEntry> modfEntries;      // Записи из чанка MODF
    std::string baseMapName;                 // Базовое имя карты, например "Karazahn"
    std::vector<std::string> adtFileNames;   // Имена существующих ADT файлов

    WDTData()
    {
        mainEntries.resize(64 * 64);
    }

    /**
     * @brief Парсит WDT файл из предоставленного буфера данных.
     * @param data Указатель на начало данных WDT файла.
     * @param size Размер данных в байтах.
     * @param mapName Базовое имя карты (например, "Karazahn") для генерации имен ADT.
     * @param outWDTData Структура для записи распарсенных данных.
     * @return true, если парсинг прошел успешно и все обязательные чанки найдены, иначе false.
     */
    bool parse(const char* data, size_t size, const std::string& mapName, WDTData& outWDTData);
};

// --- Класс парсера ---

class Parser
{
   public:
    // Структура для заголовка чанка (делаем публичной, чтобы SIZEOF_CHUNK_HEADER работал)
    struct ChunkHeader
    {
        char signature[4];  // Сигнатура чанка (например, 'MVER', 'MPHD')
        uint32_t size;      // Размер данных чанка (не включая заголовок)

        bool isValid(const char* expectedSig) const
        {
            return signature[0] == expectedSig[0] && signature[1] == expectedSig[1] && signature[2] == expectedSig[2] &&
                   signature[3] == expectedSig[3];
        }
    };

    // Общие константы для WDT, специфичные для Parser
    static constexpr size_t SIZEOF_CHUNK_HEADER = sizeof(ChunkHeader);  // 8 байт

    Parser();
    ~Parser();

    /**
     * @brief Парсит WDT файл из предоставленного буфера данных.
     * @param data Указатель на начало данных WDT файла.
     * @param size Размер данных в байтах.
     * @param outWDTData Структура для записи распарсенных данных.
     * @return true, если парсинг прошел успешно и все обязательные чанки найдены, иначе false.
     */
    bool parse(const char* data, size_t size, WDTData& outWDTData);

    // Опционально: Удобная функция для загрузки из файла
    // bool parseFromFile(const std::string& filePath, WDTData& outWDTData);

   private:
    // Приватные методы для парсинга отдельных чанков
    bool parseMVER(const char*& currentPtr, size_t& remainingSize, WDTData& outWDTData);
    bool parseMPHD(const char*& currentPtr, size_t& remainingSize, WDTData& outWDTData);
    bool parseMAIN(const char*& currentPtr, size_t& remainingSize, WDTData& outWDTData);
    bool parseMWMO(const char*& currentPtr, size_t& remainingSize, const ChunkHeader& mwmoHeader, WDTData& outWDTData);
    bool parseMODF(const char*& currentPtr, size_t& remainingSize, const ChunkHeader& modfHeader, WDTData& outWDTData);

    // Вспомогательные функции
    /**
     * @brief Читает заголовок чанка из текущей позиции.
     * @param currentPtr Указатель на текущую позицию в буфере данных. Будет сдвинут на размер заголовка.
     * @param remainingSize Оставшийся размер данных в буфере. Будет уменьшен на размер заголовка.
     * @param outHeader Структура для записи прочитанного заголовка.
     * @return true, если заголовок успешно прочитан, иначе false (например, если данных недостаточно).
     */
    bool readChunkHeader(const char*& currentPtr, size_t& remainingSize, ChunkHeader& outHeader);
};

// Общие константы для WDT
constexpr size_t WDT_MAIN_ENTRIES_COUNT = 64 * 64;

}  // namespace WDT
}  // namespace NavMeshTool
