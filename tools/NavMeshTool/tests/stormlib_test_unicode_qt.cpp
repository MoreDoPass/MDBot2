/**
 * @file stormlib_test_unicode_qt.cpp
 * @brief Тестовое приложение для проверки функциональности StormLib с Unicode и Qt логированием.
 *
 * Этот тест выполняет ряд операций с MPQ-архивом (common.mpq из WoW 3.3.5a Sirus),
 * используя Unicode-пути для доступа к MPQ-файлу, и логирует все операции через Qt QLoggingCategory.
 * Внутренние пути в MPQ обрабатываются как char*, как того требует StormLib и (listfile).
 *
 * @details Тест разработан для работы в Unicode-режиме.
 * Все вызовы функций StormLib (для внешних путей) и Windows API используют их Unicode-версии.
 * Успешное выполнение всех тестовых секций выводится через Qt-логирование.
 * В случае ошибок, выводятся соответствующие сообщения и коды ошибок GetLastError() через Qt-логирование.
 */

#include <StormLib.h>
#include <windows.h>  // Для GetLastError
#include <string>     // для std::to_string

#include <QCoreApplication>
#include <QLoggingCategory>
#include <QDebug>
#include <QString>

// Определяем категорию логирования
Q_LOGGING_CATEGORY(logStormTestUnicode, "navmesh.test.stormlib_unicode")

// Убираем redirect_io_to_console для максимального упрощения
/*
#ifdef _MSC_VER
#include <cstdio>
void redirect_io_to_console()
{
    // Перенаправляем stdout, stderr, stdin на новую консоль
    if (AllocConsole())
    {
        FILE* pCout;
        FILE* pCerr;
        FILE* pCin;
        freopen_s(&pCout, "CONOUT$", "w", stdout);
        freopen_s(&pCerr, "CONOUT$", "w", stderr);
        freopen_s(&pCin, "CONIN$", "r", stdin);
        std::cout.clear();
        std::cerr.clear();
        std::cin.clear();
    }
}
#endif
*/

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    QLoggingCategory::setFilterRules(
        "navmesh.test.stormlib_unicode.debug=true\n"
        "qt.core.logging.debug=false");  // Включаем наш лог, отключаем лишнее от Qt

    // Путь к архиву, предоставленный пользователем
    // Используем const wchar_t* и Unicode-версии функций
    const wchar_t* mpqPath = L"C:\\Games\\WoW Sirus\\World of Warcraft Sirus\\Data\\common.mpq";
    HANDLE hMpq = NULL;
    bool bOpened = false;  // Инициализируем как false

    qCInfo(logStormTestUnicode) << "Test started.";
    qCInfo(logStormTestUnicode) << "MPQ Path:" << QString::fromWCharArray(mpqPath);
    qCInfo(logStormTestUnicode) << "Calling SFileOpenArchive...";

    SetLastError(0);                      // Сбрасываем последнюю ошибку перед вызовом
    DWORD preCallError = GetLastError();  // Запоминаем ошибку до (должна быть 0)

    // SFileOpenArchive принимает TCHAR*, что в Unicode сборке будет wchar_t*
    bOpened = SFileOpenArchive(mpqPath, 0, 0, &hMpq);

    DWORD postCallError = GetLastError();  // Получаем ошибку СРАЗУ после вызова

    qCInfo(logStormTestUnicode) << "SFileOpenArchive call finished.";
    qCInfo(logStormTestUnicode) << "bOpened result:" << bOpened;
    qCInfo(logStormTestUnicode) << "hMpq handle:" << hMpq;
    qCInfo(logStormTestUnicode) << "GetLastError() before call (should be 0 if reset):" << preCallError;
    qCInfo(logStormTestUnicode) << "GetLastError() immediately after SFileOpenArchive:" << postCallError;

    if (bOpened)
    {
        qCInfo(logStormTestUnicode) << "[SUCCESS] Archive appears to be opened based on return value.";

        // --- Начало расширенных тестов ---
        // Внутренние пути остаются const char*, как и раньше, согласно README и поведению StormLib
        const char* testFilePath = "World\\Maps\\Azeroth\\Azeroth_32_25.adt";
        const char* searchMask = "world\\maps\\azeroth\\*.adt";
        // Путь для извлечения файла - это путь в файловой системе, он должен быть Unicode
        const wchar_t* extractToPath = L"temp_extraction_test\\Azeroth_32_25.adt";
        HANDLE hFile = NULL;
        DWORD dwFileSize = 0;
        char buffer[1024];  // Буфер для чтения остается char
        DWORD dwBytesRead = 0;

        // 1. SFileHasFile
        qCInfo(logStormTestUnicode) << "\n--- Test: SFileHasFile ---";
        qCInfo(logStormTestUnicode) << "Checking for file:" << testFilePath;
        SetLastError(0);
        if (SFileHasFile(hMpq, testFilePath))
        {
            qCInfo(logStormTestUnicode) << "SFileHasFile: File '" << testFilePath << "' EXISTS.";
        }
        else
        {
            qCWarning(logStormTestUnicode)
                << "SFileHasFile: File '" << testFilePath << "' DOES NOT EXIST. Error:" << GetLastError();
        }

        // 2. SFileOpenFileEx, SFileGetFileSize, SFileReadFile, SFileCloseFile
        qCInfo(logStormTestUnicode) << "\n--- Test: Open/Read/Close File ---";
        qCInfo(logStormTestUnicode) << "Attempting to open file:" << testFilePath;
        SetLastError(0);
        // SFileOpenFileEx для внутреннего пути использует const char*
        if (SFileOpenFileEx(hMpq, testFilePath, SFILE_OPEN_FROM_MPQ, &hFile))
        {
            qCInfo(logStormTestUnicode) << "SFileOpenFileEx: Successfully opened '" << testFilePath
                                        << "'. Handle:" << hFile;

            SetLastError(0);
            dwFileSize = SFileGetFileSize(hFile, NULL);
            if (dwFileSize != SFILE_INVALID_SIZE)
            {
                qCInfo(logStormTestUnicode)
                    << "SFileGetFileSize: Size of '" << testFilePath << "' is" << dwFileSize << "bytes.";
            }
            else
            {
                qCWarning(logStormTestUnicode)
                    << "SFileGetFileSize: Failed to get size for '" << testFilePath << "'. Error:" << GetLastError();
            }

            if (dwFileSize > 0 && dwFileSize != SFILE_INVALID_SIZE)
            {
                SetLastError(0);
                if (SFileReadFile(hFile, buffer, sizeof(buffer) - 1, &dwBytesRead, NULL))
                {
                    buffer[dwBytesRead] = '\0';  // Null-terminate
                    qCInfo(logStormTestUnicode) << "SFileReadFile: Successfully read" << dwBytesRead
                                                << "bytes. (Partial content shown if large)";
                    // Осторожно: не печатайте бинарные данные как строку напрямую, если это не текст
                }
                else
                {
                    qCWarning(logStormTestUnicode)
                        << "SFileReadFile: Failed to read from '" << testFilePath << "'. Error:" << GetLastError();
                }
            }

            SetLastError(0);
            if (SFileCloseFile(hFile))
            {
                qCInfo(logStormTestUnicode) << "SFileCloseFile: Successfully closed '" << testFilePath << "'.";
            }
            else
            {
                qCWarning(logStormTestUnicode)
                    << "SFileCloseFile: Failed to close '" << testFilePath << "'. Error:" << GetLastError();
            }
        }
        else
        {
            qCWarning(logStormTestUnicode)
                << "SFileOpenFileEx: Failed to open '" << testFilePath << "'. Error:" << GetLastError();
        }

        // 3. SFileFindFirstFile, SFileFindNextFile, SFileFindClose
        qCInfo(logStormTestUnicode) << "\n--- Test: File Search ---";
        qCInfo(logStormTestUnicode) << "Searching for files with mask:" << searchMask;
        SFILE_FIND_DATA sfd;  // sfd.cFileName остается char[]
        // SFileFindFirstFile для внутреннего пути использует const char*
        HANDLE hFind = SFileFindFirstFile(hMpq, searchMask, &sfd, NULL);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            qCInfo(logStormTestUnicode) << "SFileFindFirstFile: Found:" << sfd.cFileName << "(Size:" << sfd.dwFileSize
                                        << ")";
            int count = 1;
            while (SFileFindNextFile(hFind, &sfd))
            {
                qCInfo(logStormTestUnicode)
                    << "SFileFindNextFile: Found:" << sfd.cFileName << "(Size:" << sfd.dwFileSize << ")";
                count++;
                if (count >= 5)
                {  // Ограничим вывод для краткости
                    qCInfo(logStormTestUnicode) << "(Search results truncated after 5 files)";
                    break;
                }
            }
            SFileFindClose(hFind);
            qCInfo(logStormTestUnicode) << "SFileFindClose: Search finished.";
        }
        else
        {
            qCWarning(logStormTestUnicode)
                << "SFileFindFirstFile: No files found matching '" << searchMask << "'. Error:" << GetLastError();
        }

        // 4. SFileExtractFile
        qCInfo(logStormTestUnicode) << "\n--- Test: SFileExtractFile ---";
        qCInfo(logStormTestUnicode) << "Attempting to extract '" << testFilePath << "' to '"
                                    << QString::fromWCharArray(extractToPath) << "'";
        // Создадим директорию, если ее нет (для Windows) - используем Unicode версию
        std::wstring extractDirStr = L"temp_extraction_test";
        CreateDirectoryW(extractDirStr.c_str(), NULL);  // Используем CreateDirectoryW
        SetLastError(0);
        // SFileExtractFile: первый аргумент (внутренний путь) - char*, второй (внешний путь) - TCHAR* (wchar_t*)
        if (SFileExtractFile(hMpq, testFilePath, extractToPath, SFILE_OPEN_FROM_MPQ))
        {
            qCInfo(logStormTestUnicode) << "SFileExtractFile: Successfully extracted '" << testFilePath << "' to '"
                                        << QString::fromWCharArray(extractToPath) << "'.";
        }
        else
        {
            qCWarning(logStormTestUnicode)
                << "SFileExtractFile: Failed to extract '" << testFilePath << "'. Error:" << GetLastError();
        }
        // --- Конец расширенных тестов ---

        qCInfo(logStormTestUnicode) << "\nAttempting to close archive...";
        if (SFileCloseArchive(hMpq))
        {
            qCInfo(logStormTestUnicode) << "SFileCloseArchive successful.";
        }
        else
        {
            qCWarning(logStormTestUnicode) << "SFileCloseArchive FAILED. Error:" << GetLastError();
        }
    }
    else
    {
        qCCritical(logStormTestUnicode) << "[FAILURE] Archive not opened based on return value.";
        if (postCallError != 0)
        {
            LPWSTR lpMsgBuf = nullptr;  // Используем LPWSTR для Unicode
            FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                           NULL, postCallError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&lpMsgBuf, 0, NULL);
            if (lpMsgBuf)
            {
                qCCritical(logStormTestUnicode) << "Windows System Error Message for error" << postCallError << ":"
                                                << QString::fromWCharArray(lpMsgBuf);
                LocalFree(lpMsgBuf);
            }
            else
            {
                qCWarning(logStormTestUnicode)
                    << "Could not retrieve Windows system error message for error" << postCallError;
            }
        }
        else if (!bOpened && postCallError == 0)
        {
            qCCritical(logStormTestUnicode)
                << "SFileOpenArchive returned false, but GetLastError() is 0. This is unusual.";
        }
    }

    qCInfo(logStormTestUnicode) << "Test finished. Exiting.";
    // std::cin.get(); // Убираем, QCoreApplication имеет свой цикл обработки
    return app
        .exec();  // Запускаем цикл обработки событий Qt (хотя для консольного он может и не нужен, но для полноты)
    // return bOpened ? 0 : 1; // Заменим на выход из app.exec() или app.exit_code() если нужно
}