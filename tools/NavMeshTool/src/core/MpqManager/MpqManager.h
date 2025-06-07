#ifndef MPQMANAGER_H
#define MPQMANAGER_H

#include <StormLib.h>
#include <string>
#include <vector>
#include <QLoggingCategory>
#include <QObject>

Q_DECLARE_LOGGING_CATEGORY(logMpqManager)

/**
 * @brief Класс для управления MPQ архивами.
 *
 * Предоставляет функциональность для открытия, закрытия MPQ архивов,
 * а также для чтения, извлечения файлов и проверки их наличия.
 */
class MpqManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор MpqManager.
     * @param parent Родительский объект QObject для управления временем жизни.
     */
    explicit MpqManager(QObject* parent = nullptr);

    /**
     * @brief Деструктор MpqManager.
     *
     * Гарантирует, что архив будет закрыт при уничтожении объекта.
     */
    ~MpqManager();

    // Запрещаем копирование и присваивание
    MpqManager(const MpqManager&) = delete;
    MpqManager& operator=(const MpqManager&) = delete;

    /**
     * @brief Открывает базовый MPQ архив и последовательно применяет к нему указанные патчи.
     * @param baseArchivePath Путь к базовому MPQ файлу.
     * @param patchArchivePaths Список путей к MPQ файлам патчей.
     *        Патчи применяются в том порядке, в котором они указаны в списке.
     * @return true, если базовый архив успешно открыт (даже если некоторые патчи не удалось применить), иначе false.
     */
    bool openArchive(const std::string& baseArchivePath, const std::vector<std::string>& patchArchivePaths);

    /**
     * @brief Закрывает текущий открытый MPQ архив и все примененные к нему патчи.
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
    bool fileExists(const std::string& filePathInArchive) const;

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

    /**
     * @brief Получает список файлов в открытом MPQ архиве, соответствующих маске поиска.
     * @param searchMask Маска для поиска файлов (например, "*.blp", "World\Maps\*").
     *                   По умолчанию "*" - все файлы.
     * @return Вектор строк с именами найденных файлов. В случае ошибки или если архив не открыт,
     *         возвращает пустой вектор.
     */
    std::vector<std::string> listFiles(const std::string& searchMask = "*") const;

    /**
     * @brief Открывает базовый MPQ архив common.mpq и последовательно применяет к нему все патчи,
     * специфичные для клиента Sirus, на основе пути к директории игры.
     * Порядок патчей берется из внутреннего списка, соответствующего README.md.
     * @param wowDirectoryPath Путь к корневой директории клиента WoW (например, "C:/Games/WoWSirus").
     * @return true, если базовый архив common.mpq успешно открыт, иначе false.
     */
    bool openSirusInstallation(const std::string& wowDirectoryPath);

    /**
     * @brief Reads the content of a file from the MPQ archive directly into a buffer.
     * @param filePath The path of the file within the MPQ archive (e.g., "World\\Map\\Azeroth\\Azeroth.wdt").
     * @param buffer The vector to store the file's content. The vector will be resized and filled.
     * @return true if the file was read successfully, false otherwise.
     */
    bool readFileToBuffer(const std::string& filePath, std::vector<unsigned char>& buffer) const;

   private:
    HANDLE hMpq_ = nullptr;                       ///< Хэндл открытого MPQ архива.
    std::string currentArchivePath_;              ///< Путь к текущему открытому базовому архиву.
    std::vector<std::string> currentPatchPaths_;  ///< Пути к примененным патчам.
};

#endif  // MPQMANAGER_H
