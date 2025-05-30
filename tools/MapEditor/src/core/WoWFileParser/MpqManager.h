#ifndef MPQMANAGER_H
#define MPQMANAGER_H

#include <QString>
#include <QByteArray>
#include <QList>
#include <QLoggingCategory>
#include <memory>  // Для std::unique_ptr или std::vector<HANDLE>

// Включаем StormLib.h. Убедись, что CMake настроен так,
// чтобы компилятор мог найти этот заголовок.
// Обычно это <StormLib.h> или "StormLib.h" в зависимости от того, как vcpkg его предоставляет.
#include <StormLib.h>

Q_DECLARE_LOGGING_CATEGORY(mpqManagerLog)

class MpqManager
{
   public:
    /**
     * @brief Конструктор.
     * @param gamePath Путь к корневой директории игры World of Warcraft.
     */
    explicit MpqManager(const QString& gamePath);

    /**
     * @brief Деструктор. Закрывает все открытые MPQ архивы.
     */
    ~MpqManager();

    /**
     * @brief Инициализирует менеджер, находя и открывая MPQ архивы.
     * Должен быть вызван перед использованием других методов.
     * @return true, если инициализация прошла успешно и хотя бы один MPQ был открыт, иначе false.
     */
    bool initialize();

    /**
     * @brief Загружает файл из открытых MPQ архивов.
     * @param internalFilePath Внутренний путь к файлу в MPQ (например, "World\Maps\Karazahn\Karazahn.wdt").
     * @param[out] fileContent QByteArray для содержимого файла.
     * @return true, если файл успешно найден и загружен, иначе false.
     */
    bool loadFile(const QString& internalFilePath, QByteArray& fileContent);

    /**
     * @brief Проверяет, существует ли файл в открытых MPQ архивах.
     * @param internalFilePath Внутренний путь к файлу в MPQ.
     * @return true, если файл существует, иначе false.
     */
    bool fileExists(const QString& internalFilePath);

    /**
     * @brief Проверяет, был ли менеджер успешно инициализирован.
     * @return true, если инициализирован, иначе false.
     */
    bool isInitialized() const;

    /**
     * @brief Возвращает список хендлов открытых MPQ архивов.
     * @return QList<HANDLE> список хендлов. Пустой, если менеджер не инициализирован или нет открытых архивов.
     */
    QList<HANDLE> getOpenedArchiveHandles() const;

    /**
     * @brief Возвращает имя файла архива по его хендлу.
     * @param archiveHandle Хендл архива.
     * @return QString имя файла архива или пустая строка, если не найден.
     */
    QString getArchiveNameByHandle(HANDLE archiveHandle) const;

   private:
    // Структура для хранения информации об открытом архиве
    struct ArchiveInfo
    {
        HANDLE handle;
        QString name;  // Имя файла архива (например, "patch-3.mpq")
    };

    // Вспомогательный метод для попытки открыть один MPQ архив
    // bool openArchive(const QString& archivePath, int priority); // Возможно, этот метод не нужен в public/private,
    // если логика открытия будет внутри initialize

    QString m_gamePath;
    bool m_isInitialized;

    // Список имен MPQ файлов в порядке их поиска/приоритета (от высшего к низшему)
    // Этот список будет определен статически или найден в m_gamePath/Data
    const QList<QString> m_defaultMpqOrder = {
        "common.mpq"
        // "patch-4.mpq",
        // "patch-3.mpq",
        // "patch-2.mpq",
        // "patch.mpq",  // Общие патчи
        // "ruRU/patch-ruRU-4.mpq",
        // "ruRU/patch-ruRU-3.mpq",
        // "ruRU/patch-ruRU-2.mpq",
        // "ruRU/patch-ruRU.mpq",  // Патчи локализации
        // "expansion.mpq",        // The Burning Crusade
        // "lichking.mpq",         // Wrath of the Lich King
        // "ruRU/locale-ruRU.mpq",
        // "ruRU/expansion-locale-ruRU.mpq",
        // "ruRU/lichking-locale-ruRU.mpq"  // Файлы локализации
        // Добавить другие по мере необходимости, например, для классики, если потребуется
    };

    // Хранилище для хендлов открытых архивов.
    QList<ArchiveInfo> m_openedArchives;  // Теперь храним структуру ArchiveInfo
};

#endif  // MPQMANAGER_H
