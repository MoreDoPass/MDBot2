/**
 * @file test_client.cpp
 * @brief Простой тестовый клиент для NavService.
 * ... (описание без изменений)
 */

#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

const LPCWSTR PIPE_NAME = L"\\\\.\\pipe\\MyCoolNavServicePipe";
const DWORD BUFFER_SIZE = 8192;

int main()
{
    // <<< ИСПРАВЛЕНО: Используем std::wcout для вывода широких строк
    std::wcout << L"--- NavService Test Client ---" << std::endl;

    HANDLE hPipe = INVALID_HANDLE_VALUE;  // <<< ИСПРАВЛЕНО: Инициализируем сразу

    // <<< ИСПРАВЛЕНО: Используем std::wcout для вывода широких строк
    std::wcout << L"Connecting to pipe " << PIPE_NAME << L"..." << std::endl;

    try
    {
        hPipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            // GetLastError() возвращает DWORD, который можно безопасно привести к int для вывода
            throw std::runtime_error("Failed to connect to pipe. Error code: " + std::to_string(GetLastError()) +
                                     ". Is NavService running?");
        }

        // <<< ИСПРАВЛЕНО: Используем std::wcout для вывода широких строк
        std::wcout << L"Successfully connected to the server." << std::endl;

        json requestJson = {{"action", "find_path"},
                            {"request_id", 101},  // Новый ID для наглядности
                            {"data",
                             {{"map_id", 530},
                              // Твои реальные координаты (округленные для чистоты)
                              {"start", {10350.79f, -6383.50f, 38.53f}},
                              {"end", {10350.69f, -6315.87f, 29.92f}}}}};
        std::string requestString = requestJson.dump();
        // <<< ИСПРАВЛЕНО: Используем std::cout для вывода обычной строки (JSON)
        std::cout << "\nSending request:\n" << requestString << std::endl;

        DWORD bytesWritten = 0;
        BOOL success = WriteFile(hPipe, requestString.c_str(), (DWORD)requestString.length(), &bytesWritten, NULL);

        if (!success || bytesWritten != requestString.length())
        {
            throw std::runtime_error("Failed to send data to the server. Error code: " +
                                     std::to_string(GetLastError()));
        }

        // <<< ИСПРАВЛЕНО: Используем std::wcout
        std::wcout << L"\nWaiting for a response..." << std::endl;

        char buffer[BUFFER_SIZE];
        DWORD bytesRead = 0;

        success = ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL);

        if (!success || bytesRead == 0)
        {
            throw std::runtime_error("Failed to read response from the server. Error code: " +
                                     std::to_string(GetLastError()));
        }

        buffer[bytesRead] = '\0';
        std::string responseString(buffer);

        // <<< ИСПРАВЛЕНО: Используем std::cout для вывода обычной строки (JSON)
        std::cout << "\nReceived response:\n";
        json responseJson = json::parse(responseString);
        std::cout << responseJson.dump(2) << std::endl;
    }
    catch (const std::exception& e)
    {
        // <<< ИСПРАВЛЕНО: Используем std::cerr для вывода ошибок
        std::cerr << "\n[ERROR] " << e.what() << std::endl;
        if (hPipe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hPipe);
        }
        return 1;
    }

    CloseHandle(hPipe);
    // <<< ИСПРАВЛЕНО: Используем std::wcout
    std::wcout << L"\nConnection closed. Test finished." << std::endl;
    return 0;
}