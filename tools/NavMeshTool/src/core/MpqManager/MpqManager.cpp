#include "Core/MpqManager/MpqManager.h"
#include <windows.h>  // Для GetLastError()
#include <string>     // Для std::wstring
#include <locale>     // Для std::wstring_convert
#include <codecvt>    // Для std::codecvt_utf8_utf16

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

MpqManager::MpqManager() : hMpq_(nullptr)
{
    qCDebug(logMpqManager) << "MpqManager created.";
}

MpqManager::~MpqManager()
{
    if (isOpen())
    {
        closeArchive();
    }
    qCDebug(logMpqManager) << "MpqManager destroyed.";
}

bool MpqManager::openArchive(const std::string& archivePath)
{
    if (isOpen())
    {
        qCWarning(logMpqManager) << "Attempted to open archive '" << archivePath.c_str() << "' but archive '"
                                 << currentArchivePath_.c_str() << "' is already open. Please close it first.";
        return false;
    }

    SetLastError(0);
    std::wstring wArchivePath = stringToWstring(archivePath);
    if (wArchivePath.empty() && !archivePath.empty())
    {
        // Ошибка конвертации уже залогирована в stringToWstring
        qCCritical(logMpqManager) << "Failed to convert archive path to wstring: " << archivePath.c_str();
        return false;
    }

    qCDebug(logMpqManager) << "DEBUG: MpqManager::openArchive - Original archivePath (std::string):"
                           << archivePath.c_str();
    qCDebug(logMpqManager) << "DEBUG: MpqManager::openArchive - Converted wArchivePath (std::wstring):"
                           << QString::fromStdWString(wArchivePath);
    // Для более низкоуровневой проверки можно вывести байты wArchivePath, но QString::fromStdWString должно быть
    // достаточно

    if (!SFileOpenArchive(wArchivePath.c_str(), 0, 0, &hMpq_))
    {
        DWORD lastError = GetLastError();
        qCCritical(logMpqManager) << "Failed to open MPQ archive '" << archivePath.c_str()
                                  << "'. StormLib error: " << lastError;
        hMpq_ = nullptr;
        return false;
    }

    currentArchivePath_ = archivePath;  // Сохраняем оригинальный std::string путь для консистентности остальной логики
    qCDebug(logMpqManager) << "Successfully opened MPQ archive:" << archivePath.c_str();
    return true;
}

bool MpqManager::closeArchive()
{
    if (!isOpen())
    {
        qCWarning(logMpqManager) << "Attempted to close an archive, but no archive is currently open.";
        return true;  // Не ошибка, если уже закрыт
    }

    SetLastError(0);
    if (!SFileCloseArchive(hMpq_))
    {
        DWORD lastError = GetLastError();
        qCCritical(logMpqManager) << "Failed to close MPQ archive '" << currentArchivePath_.c_str()
                                  << "'. StormLib error: " << lastError;
        // hMpq_ все равно должен быть сброшен, чтобы избежать повторных попыток закрыть невалидный хэндл
        hMpq_ = nullptr;
        currentArchivePath_.clear();
        return false;
    }

    qCDebug(logMpqManager) << "Successfully closed MPQ archive:" << currentArchivePath_.c_str();
    hMpq_ = nullptr;
    currentArchivePath_.clear();
    return true;
}

bool MpqManager::isOpen() const
{
    return hMpq_ != nullptr;
}

bool MpqManager::fileExists(const std::string& filePathInArchive)
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
