#pragma once

#include <vector>
#include <string>
#include <cstdint>  // Для uint8_t и других типов

// Возможно, понадобится ссылка на MpqManager или его интерфейс,
// если парсеры будут напрямую запрашивать файлы из MPQ.
// Либо MpqManager будет передавать буфер с данными файла в парсер.
// class MpqManager; // Прямое объявление, если нужно

namespace NavMesh
{

/**
 * @brief Базовый интерфейс для всех парсеров файлов WoW.
 */
class IFileParser
{
   public:
    virtual ~IFileParser() = default;

    /**
     * @brief Загружает и парсит данные файла из буфера.
     * @param fileBuffer Буфер с данными файла.
     * @param filePath Опциональный путь к файлу (для логирования или контекста).
     * @return true, если парсинг прошел успешно, иначе false.
     */
    virtual bool parse(const std::vector<uint8_t>& fileBuffer, const std::string& filePath = "") = 0;

    // Здесь могут быть другие общие методы, например:
    // virtual bool isValid() const = 0; // Проверка, успешно ли загружен файл
    // virtual void clear() = 0;         // Очистка загруженных данных
};

}  // namespace NavMesh