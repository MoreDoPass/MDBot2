#include "core/MpqManager/MpqManager.h"
#include <windows.h>  // Для GetLastError()
#include <string>     // Для std::wstring
#include <locale>     // Для std::wstring_convert
#include <codecvt>    // Для std::codecvt_utf8_utf16
// #include "../../../../Common/Helpers/StringHelper.h"

// Определение категории логирования
// Эта строка должна быть в .cpp файле, а не в .h после Q_DECLARE_LOGGING_CATEGORY
Q_LOGGING_CATEGORY(logMpqManager, "core.mpqmanager")

// Вспомогательная функция для преобразования std::string (UTF-8) в std::wstring
std::wstring stringToWstring(const std::string& str)
{
    try
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.from_bytes(str);
    }
    catch (const std::range_error& e)
    {
        // Эта ошибка может возникнуть, если строка не является валидным UTF-8
        // или содержит символы, которые не могут быть представлены в UTF-16.
        // В таких случаях можно вернуть пустую строку или выбросить исключение.
        // Для простоты пока логируем и возвращаем пустую строку.
        qCWarning(logMpqManager) << "Failed to convert string to wstring: " << str.c_str() << ". Error: " << e.what();
        return std::wstring();
    }
}

MpqManager::MpqManager(QObject* parent) : QObject(parent), hMpq_(nullptr)
{
    qCDebug(logMpqManager) << "MpqManager created.";
}

MpqManager::~MpqManager()
{
    if (isOpen())
    {
        qCWarning(logMpqManager) << "MPQ archive was not closed prior to MpqManager destruction. Closing now.";
        closeArchive();
    }
    qCDebug(logMpqManager) << "MpqManager destroyed.";
}

bool MpqManager::openArchive(const std::string& baseArchivePath, const std::vector<std::string>& patchArchivePaths)
{
    if (isOpen())
    {
        qCWarning(logMpqManager) << "Attempted to open archive '" << baseArchivePath.c_str() << "' but archive '"
                                 << currentArchivePath_.c_str() << "' (with " << currentPatchPaths_.size()
                                 << " patches) is already open. Please close it first.";
        return false;
    }

    SetLastError(0);
    std::wstring wBaseArchivePath = stringToWstring(baseArchivePath);
    if (wBaseArchivePath.empty() && !baseArchivePath.empty())
    {
        qCCritical(logMpqManager) << "Failed to convert base archive path to wstring: " << baseArchivePath.c_str();
        return false;
    }

    qCDebug(logMpqManager) << "Attempting to open base archive: " << baseArchivePath.c_str();
    if (!SFileOpenArchive(wBaseArchivePath.c_str(), 0, MPQ_OPEN_READ_ONLY, &hMpq_))
    {
        qCCritical(logMpqManager) << "Failed to open base MPQ archive '" << baseArchivePath.c_str()
                                  << "'. Error code: " << GetLastError();
        hMpq_ = nullptr;  // Убедимся, что хэндл сброшен
        return false;
    }

    qCInfo(logMpqManager) << "Base MPQ archive '" << baseArchivePath.c_str() << "' opened successfully.";
    currentArchivePath_ = baseArchivePath;
    currentPatchPaths_.clear();  // Очистим на случай, если это повторное открытие без закрытия (хотя if (isOpen())
                                 // должен это предотвратить)

    qCDebug(logMpqManager) << "Attempting to apply" << patchArchivePaths.size() << "patch(es).";
    for (const std::string& patchPath : patchArchivePaths)
    {
        std::wstring wPatchPath = stringToWstring(patchPath);
        if (wPatchPath.empty() && !patchPath.empty())
        {
            qCWarning(logMpqManager) << "Failed to convert patch archive path to wstring: " << patchPath.c_str()
                                     << ". Skipping this patch.";
            continue;
        }

        qCDebug(logMpqManager) << "Attempting to apply patch: " << patchPath.c_str();
        SetLastError(0);
        if (!SFileOpenPatchArchive(hMpq_, wPatchPath.c_str(), nullptr, 0))
        {
            qCWarning(logMpqManager) << "Failed to apply patch MPQ archive '" << patchPath.c_str() << "' to '"
                                     << currentArchivePath_.c_str() << "'. Error code: " << GetLastError()
                                     << ". Continuing without this patch.";
        }
        else
        {
            qCInfo(logMpqManager) << "Successfully applied patch '" << patchPath.c_str() << "'.";
            currentPatchPaths_.push_back(patchPath);
        }
    }

    qCInfo(logMpqManager) << "Finished applying patches. Total patches successfully applied: "
                          << currentPatchPaths_.size() << "out of" << patchArchivePaths.size() << "attempted.";
    return true;  // Базовый архив открыт
}

bool MpqManager::closeArchive()
{
    if (!isOpen())
    {
        qCDebug(logMpqManager) << "No MPQ archive is currently open.";
        return true;  // Считаем успешным, так как нечего закрывать
    }

    qCDebug(logMpqManager) << "Closing MPQ archive: " << currentArchivePath_.c_str() << "with"
                           << currentPatchPaths_.size() << "patches.";
    SetLastError(0);
    if (!SFileCloseArchive(hMpq_))
    {
        qCCritical(logMpqManager) << "Failed to close MPQ archive '" << currentArchivePath_.c_str()
                                  << "'. Error code: " << GetLastError();
        // Не меняем состояние, чтобы можно было попытаться закрыть снова или проанализировать ошибку
        return false;
    }

    qCInfo(logMpqManager) << "MPQ archive '" << currentArchivePath_.c_str() << "' closed successfully.";
    hMpq_ = nullptr;
    currentArchivePath_.clear();
    currentPatchPaths_.clear();
    return true;
}

bool MpqManager::isOpen() const
{
    return hMpq_ != nullptr;
}

bool MpqManager::fileExists(const std::string& filePathInArchive) const
{
    if (!isOpen())
    {
        qCWarning(logMpqManager) << "Cannot check file existence for '" << filePathInArchive.c_str()
                                 << "': MPQ archive is not open.";
        return false;
    }

    SetLastError(0);

    // Убираем временный тест, используем переданный filePathInArchive
    qCDebug(logMpqManager) << "DEBUG: MpqManager::fileExists - Checking for filePathInArchive: "
                           << filePathInArchive.c_str();

    if (SFileHasFile(hMpq_, filePathInArchive.c_str()))
    {
        qCDebug(logMpqManager) << "File '" << filePathInArchive.c_str() << "' exists in archive '"
                               << currentArchivePath_.c_str() << "'.";
        return true;
    }
    else
    {
        // DWORD lastError = GetLastError(); // Можно раскомментировать для доп. отладки
        qCDebug(logMpqManager) << "File '" << filePathInArchive.c_str() << "' does NOT exist in archive '"
                               << currentArchivePath_.c_str()
                               << "'.";  // StormLib error for SFileHasFile is implicit (returns false).
        return false;
    }
}

bool MpqManager::readFile(const std::string& filePathInArchive, std::vector<unsigned char>& buffer)
{
    if (!isOpen())
    {
        qCWarning(logMpqManager) << "Cannot read file '" << filePathInArchive.c_str() << "': MPQ archive '"
                                 << currentArchivePath_.c_str() << "' is not open.";
        return false;
    }

    HANDLE hFile = nullptr;
    SetLastError(0);
    if (!SFileOpenFileEx(hMpq_, filePathInArchive.c_str(), SFILE_OPEN_FROM_MPQ, &hFile))
    {
        DWORD lastError = GetLastError();
        qCCritical(logMpqManager) << "Failed to open file '" << filePathInArchive.c_str() << "' from archive '"
                                  << currentArchivePath_.c_str() << "'. StormLib error: " << lastError;
        return false;
    }

    SetLastError(0);
    DWORD dwFileSize = SFileGetFileSize(hFile, nullptr);
    if (dwFileSize == SFILE_INVALID_SIZE)
    {
        DWORD lastError = GetLastError();
        qCCritical(logMpqManager) << "Failed to get size for file '" << filePathInArchive.c_str() << "' in archive '"
                                  << currentArchivePath_.c_str() << "'. StormLib error: " << lastError;
        SFileCloseFile(hFile);
        return false;
    }
    if (dwFileSize == 0)
    {
        qCWarning(logMpqManager) << "File '" << filePathInArchive.c_str() << "' in archive '"
                                 << currentArchivePath_.c_str() << "' is empty.";
        buffer.clear();
        SFileCloseFile(hFile);
        return true;  // Успешно прочитали пустой файл
    }

    buffer.resize(dwFileSize);
    DWORD dwBytesRead = 0;
    SetLastError(0);
    if (!SFileReadFile(hFile, buffer.data(), dwFileSize, &dwBytesRead, nullptr))
    {
        DWORD lastError = GetLastError();
        qCCritical(logMpqManager) << "Failed to read file '" << filePathInArchive.c_str() << "' from archive '"
                                  << currentArchivePath_.c_str() << "'. StormLib error: " << lastError;
        SFileCloseFile(hFile);
        buffer.clear();  // Очистить буфер при ошибке
        return false;
    }

    if (dwBytesRead != dwFileSize)
    {
        qCWarning(logMpqManager) << "Read incomplete for file '" << filePathInArchive.c_str() << "' from archive '"
                                 << currentArchivePath_.c_str() << "'. Expected " << dwFileSize << " bytes, got "
                                 << dwBytesRead << " bytes.";
        // Можно решить, считать ли это ошибкой или нет. Пока считаем частичное чтение ошибкой.
        SFileCloseFile(hFile);
        buffer.clear();
        return false;
    }

    qCDebug(logMpqManager) << "Successfully read " << dwBytesRead << " bytes from file '" << filePathInArchive.c_str()
                           << "' in archive '" << currentArchivePath_.c_str() << "'.";
    SFileCloseFile(hFile);
    return true;
}

bool MpqManager::extractFile(const std::string& filePathInArchive, const std::string& outputPath)
{
    if (!isOpen())
    {
        qCWarning(logMpqManager) << "Cannot extract file '" << filePathInArchive.c_str() << "': MPQ archive '"
                                 << currentArchivePath_.c_str() << "' is not open.";
        return false;
    }

    SetLastError(0);
    std::wstring wOutputPath = stringToWstring(outputPath);
    if (wOutputPath.empty() && !outputPath.empty())
    {
        qCCritical(logMpqManager) << "Failed to convert output path to wstring: " << outputPath.c_str();
        return false;
    }

    if (!SFileExtractFile(hMpq_, filePathInArchive.c_str(), wOutputPath.c_str(), SFILE_OPEN_FROM_MPQ))
    {
        DWORD lastError = GetLastError();
        qCCritical(logMpqManager) << "Failed to extract file '" << filePathInArchive.c_str() << "' from archive '"
                                  << currentArchivePath_.c_str() << "' to '"
                                  << outputPath.c_str()  // Логируем оригинальный outputPath
                                  << "'. StormLib error: " << lastError;
        return false;
    }

    qCDebug(logMpqManager) << "Successfully extracted file '" << filePathInArchive.c_str() << "' from archive '"
                           << currentArchivePath_.c_str() << "' to '" << outputPath.c_str() << "'.";
    return true;
}

std::vector<std::string> MpqManager::listFiles(const std::string& searchMask) const
{
    std::vector<std::string> foundFiles;
    if (!isOpen())
    {
        qCWarning(logMpqManager) << "Cannot list files: MPQ archive '" << currentArchivePath_.c_str()
                                 << "' is not open.";
        return foundFiles;  // Возвращаем пустой вектор
    }

    qCDebug(logMpqManager) << "Listing files in archive '" << currentArchivePath_.c_str() << "' with mask '"
                           << searchMask.c_str() << "'.";

    SFILE_FIND_DATA findData;
    SetLastError(0);
    HANDLE hFind = SFileFindFirstFile(hMpq_, searchMask.c_str(), &findData, nullptr);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        DWORD lastError = GetLastError();
        // Ошибка ERROR_NO_MORE_FILES (18) ожидаема, если ничего не найдено
        if (lastError == ERROR_NO_MORE_FILES)
        {
            qCDebug(logMpqManager) << "No files found matching mask '" << searchMask.c_str() << "' in archive '"
                                   << currentArchivePath_.c_str() << "'.";
        }
        else
        {
            qCWarning(logMpqManager) << "Failed to find first file with mask '" << searchMask.c_str()
                                     << "' in archive '" << currentArchivePath_.c_str()
                                     << "'. StormLib error: " << lastError;
        }
        return foundFiles;  // Возвращаем пустой вектор
    }

    do
    {
        foundFiles.push_back(findData.cFileName);
    } while (SFileFindNextFile(hFind, &findData));

    DWORD lastErrorAfterLoop = GetLastError();
    if (lastErrorAfterLoop != ERROR_NO_MORE_FILES)
    {
        // Логируем, если SFileFindNextFile завершился не с ERROR_NO_MORE_FILES
        qCWarning(logMpqManager) << "SFileFindNextFile finished with unexpected error code: " << lastErrorAfterLoop
                                 << "while listing files with mask '" << searchMask.c_str() << "'.";
    }

    if (!SFileFindClose(hFind))
    {
        qCWarning(logMpqManager) << "Failed to close file search handle for mask '" << searchMask.c_str()
                                 << "' in archive '" << currentArchivePath_.c_str()
                                 << "'. Error code: " << GetLastError();
    }

    qCDebug(logMpqManager) << "Found" << foundFiles.size() << "file(s) matching mask '" << searchMask.c_str() << "'.";
    return foundFiles;
}

bool MpqManager::openSirusInstallation(const std::string& wowDirectoryPath)
{
    if (isOpen())
    {
        qCWarning(logMpqManager) << "Attempted to open Sirus installation, but an archive is already open."
                                 << "Please close the current archive first.";
        return false;
    }

    std::string baseMpqRelativePath = "Data/common.mpq";
    std::string baseArchivePath = wowDirectoryPath + "/" + baseMpqRelativePath;

    // Список патчей согласно README.md (относительно wowDirectoryPath)
    // Важно: порядок должен строго соответствовать порядку загрузки клиентом
    const std::vector<std::string> patchRelativePaths = {
        "Data/ruRU/locale-ruRU.mpq", "Data/patch.mpq", "Data/patch-2.mpq", "Data/patch-3.mpq",
        "Data/patch-4.MPQ",  // Обрати внимание на регистр .MPQ, если это важно для твоей ФС или StormLib
        "Data/patch-5.MPQ", "Data/patch-6.MPQ", "Data/patch-7.mpq", "Data/patch-8.mpq", "Data/patch-9.mpq",
        "Data/patch-a.mpq", "Data/patch-b.mpq", "Data/patch-c.mpq", "Data/patch-d.mpq", "Data/patch-e.mpq",
        "Data/patch-f.mpq", "Data/patch-g.mpq", "Data/patch-h.mpq", "Data/patch-i.mpq", "Data/patch-j.mpq",
        "Data/patch-k.mpq", "Data/patch-l.mpq", "Data/patch-m.mpq", "Data/patch-n.mpq", "Data/patch-o.mpq",
        "Data/patch-p.mpq", "Data/patch-q.mpq",
        // Патчи локализации из Data/ruRU/
        "Data/ruRU/patch-ruRU.mpq", "Data/ruRU/patch-ruRU-4.mpq", "Data/ruRU/patch-ruRU-5.mpq",
        "Data/ruRU/patch-ruRU-6.mpq", "Data/ruRU/patch-ruRU-7.mpq", "Data/ruRU/patch-ruRU-8.mpq",
        "Data/ruRU/patch-ruRU-a.mpq", "Data/ruRU/patch-ruRU-b.mpq", "Data/ruRU/patch-ruRU-c.mpq",
        "Data/ruRU/patch-ruRU-d.mpq", "Data/ruRU/patch-ruRU-e.mpq", "Data/ruRU/patch-ruRU-f.mpq",
        "Data/ruRU/patch-ruRU-i.mpq", "Data/ruRU/patch-ruRU-j.mpq", "Data/ruRU/patch-ruRU-k.mpq"
        // Заметка из README: "Для генерации NavMesh рекомендуется передавать ... ИСКЛЮЧАЯ все архивы из ...
        // Data/ruRU/." Текущая реализация включает все патчи для полноты. Если для NavMesh нужен другой набор, можно
        // будет создать отдельную функцию или передавать флаг.
    };

    std::vector<std::string> patchArchivePaths;
    patchArchivePaths.reserve(patchRelativePaths.size());
    for (const std::string& relativePath : patchRelativePaths)
    {
        patchArchivePaths.push_back(wowDirectoryPath + "/" + relativePath);
    }

    qCDebug(logMpqManager) << "Attempting to open Sirus WoW installation.";
    qCDebug(logMpqManager) << "Base archive:" << baseArchivePath.c_str();
    qCDebug(logMpqManager) << "Number of patches to apply:" << patchArchivePaths.size();

    return openArchive(baseArchivePath, patchArchivePaths);
}

bool MpqManager::readFileToBuffer(const std::string& filePath, std::vector<unsigned char>& buffer) const
{
    buffer.clear();  // Очищаем буфер перед использованием
    if (!isOpen())
    {
        qCWarning(logMpqManager) << "Cannot read file to buffer: Archive is not open.";
        return false;
    }

    HANDLE hFile = nullptr;
    // StormLib ожидает пути в формате OEM или UTF-8 для функций A (char*)
    // или UTF-16 для функций W (wchar_t*).
    // Мы используем SFileOpenFileEx, которая обычно работает с текущей кодировкой системы,
    // но для надежности лучше придерживаться char* для имен файлов внутри MPQ, если они в ASCII/UTF-8.
    // Если есть проблемы с русскими именами файлов, потребуется конвертация в std::wstring и использование
    // SFileOpenFileExW или убедиться, что StormLib скомпилирован с поддержкой UTF-8 для имен файлов. Пока предполагаем,
    // что filePath в корректной для StormLib кодировке (обычно ANSI/UTF-8 для имен файлов внутри MPQ).

    if (!SFileOpenFileEx(hMpq_, filePath.c_str(), SFILE_OPEN_FROM_MPQ, &hFile))
    {
        qCWarning(logMpqManager) << "Failed to open file" << filePath.c_str() << "in MPQ. Error:" << GetLastError();
        return false;
    }

    DWORD dwFileSize = SFileGetFileSize(hFile, nullptr);
    if (dwFileSize == SFILE_INVALID_SIZE)
    {
        qCWarning(logMpqManager) << "Failed to get size for file" << filePath.c_str()
                                 << "in MPQ. Error:" << GetLastError();
        SFileCloseFile(hFile);
        return false;
    }

    if (dwFileSize == 0)  // Файл пуст
    {
        qCDebug(logMpqManager) << "File" << filePath.c_str() << "is empty.";
        SFileCloseFile(hFile);
        return true;  // Успешно прочитали пустой файл
    }

    buffer.resize(dwFileSize);
    DWORD dwBytesRead = 0;
    if (!SFileReadFile(hFile, buffer.data(), dwFileSize, &dwBytesRead, nullptr) || dwBytesRead != dwFileSize)
    {
        qCWarning(logMpqManager) << "Failed to read file" << filePath.c_str() << "from MPQ. Bytes read:" << dwBytesRead
                                 << "Expected:" << dwFileSize << "Error:" << GetLastError();
        SFileCloseFile(hFile);
        buffer.clear();  // Очищаем буфер при ошибке чтения
        return false;
    }

    SFileCloseFile(hFile);
    qCDebug(logMpqManager) << "Successfully read" << dwBytesRead << "bytes from" << filePath.c_str() << "into buffer.";
    return true;
}
