/**
 * @file stormlib_test.cpp
 * @brief Тестовое приложение для проверки функциональности библиотеки StormLib.
 *
 * Этот тест выполняет ряд операций с MPQ-архивом (common.mpq из WoW 3.3.5a Sirus),
 * включая открытие/закрытие архива, проверку наличия файлов, чтение файлов,
 * поиск файлов по маске и извлечение файлов.
 *
 * @details Тест разработан для работы в ANSI-режиме (без определения UNICODE/ _UNICODE
 * на уровне проекта или в коде), используя char* для путей и имен файлов.
 * Все вызовы функций StormLib и Windows API используют их ANSI-версии.
 * Успешное выполнение всех тестовых секций выводится в консоль.
 * В случае ошибок, выводятся соответствующие сообщения и коды ошибок GetLastError().
 */

#include <StormLib.h>
#include <iostream>
#include <windows.h>  // Для GetLastError
#include <string>     // для std::to_string

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
    // #ifdef _MSC_VER
    // redirect_io_to_console();
    // #endif

    // Путь к архиву, предоставленный пользователем
    // Используем const char* и SFileOpenArchiveA
    const char* mpqPath = "C:\\Games\\WoW Sirus\\World of Warcraft Sirus\\Data\\common.mpq";
    HANDLE hMpq = NULL;
    bool bOpened = false;  // Инициализируем как false

    std::cout << "Test started." << std::endl;
    std::cout << "MPQ Path: " << mpqPath << std::endl;
    std::cout << "Calling SFileOpenArchive..." << std::endl;

    SetLastError(0);                      // Сбрасываем последнюю ошибку перед вызовом
    DWORD preCallError = GetLastError();  // Запоминаем ошибку до (должна быть 0)

    // Возвращаемся к простому SFileOpenArchive с char*
    // bOpened = SFileOpenArchiveExA(mpqPath, 0 /*priority*/, MPQ_OPEN_READ_ONLY, &hMpq, 0 /*dwStreamFlags - пробуем
    // 0*/);
    bOpened = SFileOpenArchive(mpqPath, 0, 0, &hMpq);

    DWORD postCallError = GetLastError();  // Получаем ошибку СРАЗУ после вызова

    std::cout << "SFileOpenArchive call finished." << std::endl;
    std::cout << "bOpened result: " << (bOpened ? "true" : "false") << std::endl;
    std::cout << "hMpq handle: " << hMpq << std::endl;
    std::cout << "GetLastError() before call (should be 0 if reset): " << preCallError << std::endl;
    std::cout << "GetLastError() immediately after SFileOpenArchive: " << postCallError << std::endl;

    if (bOpened)
    {
        std::cout << "[SUCCESS] Archive appears to be opened based on return value." << std::endl;

        // --- Начало расширенных тестов ---
        const char* testFilePath = "World\\Maps\\Azeroth\\Azeroth_32_25.adt";  // Используем реальное имя файла
        const char* searchMask = "world\\maps\\azeroth\\*.adt";  // Оставим в нижнем регистре для теста поиска
        const char* extractToPath = "temp_extraction_test\\Azeroth_32_25.adt";  // Обновим имя извлекаемого файла
        HANDLE hFile = NULL;
        DWORD dwFileSize = 0;
        char buffer[1024];
        DWORD dwBytesRead = 0;

        // 1. SFileHasFile
        std::cout << "\n--- Test: SFileHasFile ---" << std::endl;
        std::cout << "Checking for file: " << testFilePath << std::endl;
        SetLastError(0);
        if (SFileHasFile(hMpq, testFilePath))
        {
            std::cout << "SFileHasFile: File '" << testFilePath << "' EXISTS." << std::endl;
        }
        else
        {
            std::cerr << "SFileHasFile: File '" << testFilePath << "' DOES NOT EXIST. Error: " << GetLastError()
                      << std::endl;
        }

        // 2. SFileOpenFileEx, SFileGetFileSize, SFileReadFile, SFileCloseFile
        std::cout << "\n--- Test: Open/Read/Close File ---" << std::endl;
        std::cout << "Attempting to open file: " << testFilePath << std::endl;
        SetLastError(0);
        if (SFileOpenFileEx(hMpq, testFilePath, SFILE_OPEN_FROM_MPQ, &hFile))
        {
            std::cout << "SFileOpenFileEx: Successfully opened '" << testFilePath << "'. Handle: " << hFile
                      << std::endl;

            SetLastError(0);
            dwFileSize = SFileGetFileSize(hFile, NULL);
            if (dwFileSize != SFILE_INVALID_SIZE)
            {
                std::cout << "SFileGetFileSize: Size of '" << testFilePath << "' is " << dwFileSize << " bytes."
                          << std::endl;
            }
            else
            {
                std::cerr << "SFileGetFileSize: Failed to get size for '" << testFilePath
                          << "'. Error: " << GetLastError() << std::endl;
            }

            if (dwFileSize > 0 && dwFileSize != SFILE_INVALID_SIZE)
            {
                SetLastError(0);
                if (SFileReadFile(hFile, buffer, sizeof(buffer) - 1, &dwBytesRead, NULL))
                {
                    buffer[dwBytesRead] = '\0';  // Null-terminate
                    std::cout << "SFileReadFile: Successfully read " << dwBytesRead
                              << " bytes. (Partial content shown if large)" << std::endl;
                    // Осторожно: не печатайте бинарные данные как строку напрямую, если это не текст
                }
                else
                {
                    std::cerr << "SFileReadFile: Failed to read from '" << testFilePath
                              << "'. Error: " << GetLastError() << std::endl;
                }
            }

            SetLastError(0);
            if (SFileCloseFile(hFile))
            {
                std::cout << "SFileCloseFile: Successfully closed '" << testFilePath << "'." << std::endl;
            }
            else
            {
                std::cerr << "SFileCloseFile: Failed to close '" << testFilePath << "'. Error: " << GetLastError()
                          << std::endl;
            }
        }
        else
        {
            std::cerr << "SFileOpenFileEx: Failed to open '" << testFilePath << "'. Error: " << GetLastError()
                      << std::endl;
        }

        // 3. SFileFindFirstFile, SFileFindNextFile, SFileFindClose
        std::cout << "\n--- Test: File Search ---" << std::endl;
        std::cout << "Searching for files with mask: " << searchMask << std::endl;
        SFILE_FIND_DATA sfd;
        HANDLE hFind = SFileFindFirstFile(hMpq, searchMask, &sfd, NULL);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            std::cout << "SFileFindFirstFile: Found: " << sfd.cFileName << " (Size: " << sfd.dwFileSize << ")"
                      << std::endl;
            int count = 1;
            while (SFileFindNextFile(hFind, &sfd))
            {
                std::cout << "SFileFindNextFile: Found: " << sfd.cFileName << " (Size: " << sfd.dwFileSize << ")"
                          << std::endl;
                count++;
                if (count >= 5)
                {  // Ограничим вывод для краткости
                    std::cout << "(Search results truncated after 5 files)" << std::endl;
                    break;
                }
            }
            SFileFindClose(hFind);
            std::cout << "SFileFindClose: Search finished." << std::endl;
        }
        else
        {
            std::cerr << "SFileFindFirstFile: No files found matching '" << searchMask << "'. Error: " << GetLastError()
                      << std::endl;
        }

        // 4. SFileExtractFile
        std::cout << "\n--- Test: SFileExtractFile ---" << std::endl;
        std::cout << "Attempting to extract '" << testFilePath << "' to '" << extractToPath << "'" << std::endl;
        // Создадим директорию, если ее нет (для Windows)
        std::string extractDir = "temp_extraction_test";
        CreateDirectoryA(extractDir.c_str(), NULL);
        SetLastError(0);
        if (SFileExtractFile(hMpq, testFilePath, extractToPath, SFILE_OPEN_FROM_MPQ))
        {
            std::cout << "SFileExtractFile: Successfully extracted '" << testFilePath << "' to '" << extractToPath
                      << "'." << std::endl;
        }
        else
        {
            std::cerr << "SFileExtractFile: Failed to extract '" << testFilePath << "'. Error: " << GetLastError()
                      << std::endl;
        }
        // --- Конец расширенных тестов ---

        std::cout << "\nAttempting to close archive..." << std::endl;
        if (SFileCloseArchive(hMpq))
        {
            std::cout << "SFileCloseArchive successful." << std::endl;
        }
        else
        {
            std::cerr << "SFileCloseArchive FAILED. Error: " << GetLastError() << std::endl;
        }
    }
    else
    {
        std::cerr << "[FAILURE] Archive not opened based on return value." << std::endl;
        // Ошибка postCallError уже должна содержать код ошибки от StormLib/Windows
        // Если postCallError == 0, но bOpened == false, это странно и может указывать на проблему в StormLib
        if (postCallError != 0)
        {
            LPVOID lpMsgBuf;
            FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                           NULL, postCallError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
            if (lpMsgBuf)
            {
                std::cerr << "Windows System Error Message for error " << postCallError << ": " << (LPCSTR)lpMsgBuf
                          << std::endl;
                LocalFree(lpMsgBuf);
            }
            else
            {
                std::cerr << "Could not retrieve Windows system error message for error " << postCallError << std::endl;
            }
        }
        else if (!bOpened && postCallError == 0)
        {
            std::cerr << "SFileOpenArchive returned false, but GetLastError() is 0. This is unusual." << std::endl;
        }
    }

    std::cout << "Test finished. Press Enter to exit." << std::endl;
    std::cin.get();

    return bOpened ? 0 : 1;
}