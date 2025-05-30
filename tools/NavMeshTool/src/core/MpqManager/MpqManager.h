#ifndef MPQMANAGER_H
#define MPQMANAGER_H

#include <StormLib.h>
#include <string>
#include <vector>
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(logMpqManager)

/**
 * @brief Класс для управления MPQ архивами.
 *
 * Предоставляет функциональность для открытия, закрытия MPQ архивов,
 * а также для чтения, извлечения файлов и проверки их наличия.
 */
class MpqManager
{
   public:
    /**
     * @brief Конструктор MpqManager.
     */
    MpqManager();

    /**
     * @brief Деструктор MpqManager.
     *
     * Гарантирует, что архив будет закрыт при уничтожении объекта.
     */
    ~MpqManager();

    /**
     * @brief Открывает MPQ архив.
     * @param archivePath Путь к MPQ файлу.
     * @return true, если архив успешно открыт, иначе false.
     */
    bool openArchive(const std::string& archivePath);

    /**
     * @brief Закрывает текущий открытый MPQ архив.
     * @return true, если архив успешно закрыт или не был открыт, иначе false.
     */
    bool closeArchive();

    /**
     * @brief Проверяет, открыт ли MPQ архив.
     * @return true, если архив открыт, иначе false.
     */
    bool isOpen() const;

    /**
     * @brief Проверяет наличие файла в открытом MPQ архиве.
     * @param filePathInArchive Путь к файлу внутри архива.
     * @return true, если файл существует, иначе false.
     */
    bool fileExists(const std::string& filePathInArchive);

    /**
     * @brief Читает файл из открытого MPQ архива в буфер.
     * @param filePathInArchive Путь к файлу внутри архива.
     * @param buffer Ссылка на вектор байт, куда будут загружены данные файла.
     * @return true, если файл успешно прочитан, иначе false.
     */
    bool readFile(const std::string& filePathInArchive, std::vector<unsigned char>& buffer);

    /**
     * @brief Извлекает файл из открытого MPQ архива на диск.
     * @param filePathInArchive Путь к файлу внутри архива.
     * @param outputPath Путь на диске, куда будет извлечен файл.
     * @return true, если файл успешно извлечен, иначе false.
     */
    bool extractFile(const std::string& filePathInArchive, const std::string& outputPath);

   private:
    HANDLE hMpq_ = nullptr;           ///< Хэндл открытого MPQ архива.
    std::string currentArchivePath_;  ///< Путь к текущему открытому архиву.
};

#endif  // MPQMANAGER_H
