#include "DBCParser.h"
#include <cstring>  // Для memcpy
#include <QLoggingCategory>

// Определяем категорию логирования для нашего парсера.
// "navmesh.dbcparser" - уникальное имя категории для настройки в main.cpp
Q_LOGGING_CATEGORY(logDBCParser, "navmesh.dbcparser")

namespace
{
// Пакуем структуру, чтобы компилятор не добавлял выравнивание.
// Это гарантирует, что размер структуры будет точно соответствовать данным в файле.
#pragma pack(push, 1)
/**
 * @struct DBCHeader
 * @brief Внутренняя структура, представляющая заголовок .dbc файла.
 *
 * Эта структура является деталью реализации и используется только внутри .cpp файла.
 * Она точно соответствует формату заголовка в файлах DBC версии 3.3.5a.
 */
struct DBCHeader
{
    /** @brief Сигнатура файла, всегда 'WDBC' (0x43424457 в little-endian). */
    uint32_t magic;
    /** @brief Количество записей (строк) в файле. */
    uint32_t recordCount;
    /** @brief Количество полей (столбцов) в каждой записи. */
    uint32_t fieldCount;
    /** @brief Размер одной записи в байтах. */
    uint32_t recordSize;
    /** @brief Общий размер блока, в котором хранятся все строки. */
    uint32_t stringBlockSize;
};
#pragma pack(pop)
}  // namespace

std::vector<MapRecord> DBCParser::parse(const std::vector<char>& data) const
{
    // 1. Проверка на минимальный размер файла
    if (data.size() < sizeof(DBCHeader))
    {
        qCCritical(logDBCParser) << "DBC file is too small to contain a valid header. Size:" << data.size();
        return {};
    }

    // 2. Чтение заголовка
    DBCHeader header;
    std::memcpy(&header, data.data(), sizeof(DBCHeader));

    // 3. Валидация заголовка
    // 'WDBC' в little-endian представлении
    constexpr uint32_t expectedMagic = 0x43424457;
    if (header.magic != expectedMagic)
    {
        qCCritical(logDBCParser) << "Invalid DBC magic signature. Expected" << Qt::hex << expectedMagic << "but got"
                                 << Qt::hex << header.magic;
        return {};
    }

    qCInfo(logDBCParser) << "DBC Header parsed successfully:" << "Records:" << header.recordCount
                         << "| Fields:" << header.fieldCount << "| Record Size:" << header.recordSize
                         << "| String Block Size:" << header.stringBlockSize;

    // 4. Проверка на целостность файла (общий размер)
    const size_t expectedTotalSize =
        sizeof(DBCHeader) + header.recordCount * header.recordSize + header.stringBlockSize;
    if (data.size() < expectedTotalSize)
    {
        qCWarning(logDBCParser) << "DBC file might be corrupted or incomplete. Expected size:" << expectedTotalSize
                                << ", actual size:" << data.size();
        // Мы можем попытаться продолжить, но это может привести к падению.
        // Для надежности лучше выйти.
        return {};
    }

    // 5. Определение указателей на блоки данных и строк
    const char* recordBlock = data.data() + sizeof(DBCHeader);
    const char* stringBlock = recordBlock + header.recordCount * header.recordSize;

    std::vector<MapRecord> results;
    results.reserve(header.recordCount);  // Сразу резервируем память для эффективности

    // 6. Итерация по всем записям
    for (uint32_t i = 0; i < header.recordCount; ++i)
    {
        const char* recordPtr = recordBlock + i * header.recordSize;

        // Согласно wowdev.wiki для Map.dbc (3.3.5a):
        // Поле 0: ID (uint32_t)
        // Поле 1: Смещение на внутреннее имя (uint32_t)
        // Поле 5: Смещение на отображаемое имя (enUS) (uint32_t)
        // Каждое поле - 4 байта.

        // Извлекаем ID
        uint32_t mapId;
        std::memcpy(&mapId, recordPtr, sizeof(uint32_t));

        // Извлекаем смещение для внутреннего имени
        uint32_t internalNameOffset;
        std::memcpy(&internalNameOffset, recordPtr + 1 * sizeof(uint32_t), sizeof(uint32_t));

        // Извлекаем смещение для отображаемого имени
        uint32_t displayNameOffset;
        std::memcpy(&displayNameOffset, recordPtr + 5 * sizeof(uint32_t), sizeof(uint32_t));

        // 7. Проверка корректности смещений и извлечение строк
        if (internalNameOffset >= header.stringBlockSize || displayNameOffset >= header.stringBlockSize)
        {
            qCWarning(logDBCParser) << "Record" << i << "for map ID" << mapId << "has invalid string offset. Skipping.";
            continue;
        }

        const char* internalNamePtr = stringBlock + internalNameOffset;
        const char* displayNamePtr = stringBlock + displayNameOffset;

        MapRecord record;
        record.id = mapId;
        // Конструктор std::string сам остановится на первом нулевом символе
        record.internalName = std::string(internalNamePtr);
        record.displayName = std::string(displayNamePtr);

        results.push_back(record);
    }

    qCInfo(logDBCParser) << "Successfully parsed" << results.size() << "records from DBC file.";
    return results;
}
