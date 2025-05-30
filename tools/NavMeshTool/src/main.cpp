#include <iostream>
#include <string>
#include <vector>
#include <windows.h>                     // Для SetConsoleOutputCP и GetConsoleCP
#include "Core/MpqManager/MpqManager.h"  // Предполагается, что CMake настроит пути

// Вспомогательная функция для вывода вектора байт (частично)
void printBuffer(const std::vector<unsigned char>& buffer, size_t maxBytesToShow = 32)
{
    for (size_t i = 0; i < buffer.size() && i < maxBytesToShow; ++i)
    {
        // Выводим в HEX формате
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    if (buffer.size() > maxBytesToShow)
    {
        std::cout << "...";
    }
    std::cout << std::dec << std::endl;  // Возвращаем десятичный вывод
}

int main(int argc, char* argv[])
{
    // Попытка настроить кодировку консоли на UTF-8 для корректного вывода кириллицы, если она будет в логах
    // Это может не сработать на всех системах или потребовать настройки шрифта консоли
    UINT oldCp = GetConsoleCP();
    UINT oldOutCp = GetConsoleOutputCP();
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "NavMeshTool MpqManager Test" << std::endl;
    std::cout << "---------------------------" << std::endl;

    MpqManager mpqManager;

    const std::string archivePath = "C:/Games/WoW Sirus/World of Warcraft Sirus/Data/patch-o.mpq";

    // Основной файл для извлечения и тестирования, путь из listfile
    const std::string fileToExtractAndTest =
        "world\\maps\\azjolarena\\azjolarena_31_31.adt";  // Используем \\ для обратного слеша
    const std::string extractedFilePath = "azjolarena_31_31_extracted.adt";

    // Файлы для проверки "наличия папок" (взяты из вашего listfile)
    const std::string creatureTestFile = "Creature\\argusfelstalkermount\\argusfelstalkermount.m2";
    const std::string dungeonsTestFile = "dungeons\\textures\\8fk_forsaken\\8fk_doorframe01.blp";
    const std::string itemTestFile = "item\\objectcomponents\\Head\\Helm_Plate_A_02IronforgeGuard_WoF.M2";
    const std::string soundTestFile = "sound\\ambience\\zoneambience\\amb_helheim_boat_base_interior.ogg";
    const std::string spellsTestFile = "spells\\glow_256.blp";
    // worldTestFile будет fileToExtractAndTest

    // Тест с прямыми слешами для сравнения (ожидаем FAIL, если регистр и слеши важны)
    const std::string fileWithForwardSlashesUpper = "World/maps/azjolarena/azjolarena_31_31.adt";

    // Тест для (listfile)
    const std::string listFileInternal = "(listfile)";

    std::cout << "DEBUG: Checking path access for: \"" << archivePath << "\"" << std::endl;
    HANDLE testFileHandle = CreateFileA(archivePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (testFileHandle == INVALID_HANDLE_VALUE)
    {
        std::cout << "DEBUG: CreateFileA FAILED! GetLastError: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "DEBUG: CreateFileA SUCCEEDED! Path seems accessible." << std::endl;
        CloseHandle(testFileHandle);
    }

    std::cout << "Attempting to open archive: " << archivePath << std::endl;
    if (mpqManager.openArchive(archivePath))
    {
        std::cout << "[SUCCESS] Archive opened: " << archivePath << std::endl;

        // 1. Проверка существования файла (основной тестовый файл - правильный путь из listfile)
        std::cout << "\n--- Test: fileExists (main extract target - correct path) ---" << std::endl;
        std::cout << "Checking for file: " << fileToExtractAndTest << std::endl;
        if (mpqManager.fileExists(fileToExtractAndTest))
        {
            std::cout << "[SUCCESS] File exists: " << fileToExtractAndTest << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] File does NOT exist: " << fileToExtractAndTest << std::endl;
        }

        // Проверка "папок" (файлы из listfile)
        std::cout << "\n--- Test: fileExists (folder indicators from listfile) ---" << std::endl;
        std::cout << "Checking for Creature file: " << creatureTestFile << std::endl;
        if (mpqManager.fileExists(creatureTestFile))
        {
            std::cout << "[SUCCESS] Creature file indicator exists." << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] Creature file indicator does NOT exist: " << creatureTestFile << std::endl;
        }

        std::cout << "Checking for Dungeons file: " << dungeonsTestFile << std::endl;
        if (mpqManager.fileExists(dungeonsTestFile))
        {
            std::cout << "[SUCCESS] Dungeons file indicator exists." << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] Dungeons file indicator does NOT exist: " << dungeonsTestFile << std::endl;
        }

        std::cout << "Checking for Item file: " << itemTestFile << std::endl;
        if (mpqManager.fileExists(itemTestFile))
        {
            std::cout << "[SUCCESS] Item file indicator exists." << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] Item file indicator does NOT exist: " << itemTestFile << std::endl;
        }

        std::cout << "Checking for Sound file: " << soundTestFile << std::endl;
        if (mpqManager.fileExists(soundTestFile))
        {
            std::cout << "[SUCCESS] Sound file indicator exists." << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] Sound file indicator does NOT exist: " << soundTestFile << std::endl;
        }

        std::cout << "Checking for Spells file: " << spellsTestFile << std::endl;
        if (mpqManager.fileExists(spellsTestFile))
        {
            std::cout << "[SUCCESS] Spells file indicator exists." << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] Spells file indicator does NOT exist: " << spellsTestFile << std::endl;
        }

        // Проверка с некорректными слешами и регистром (ожидаем FAIL)
        std::cout << "\n--- Test: fileExists (with forward slashes and wrong case) ---" << std::endl;
        std::cout << "Checking for file: " << fileWithForwardSlashesUpper << std::endl;
        if (mpqManager.fileExists(fileWithForwardSlashesUpper))
        {
            std::cout << "[UNEXPECTED SUCCESS] File exists (with forward slashes and wrong case): "
                      << fileWithForwardSlashesUpper << std::endl;
        }
        else
        {
            std::cout << "[EXPECTED FAILURE] File does NOT exist (with forward slashes and wrong case): "
                      << fileWithForwardSlashesUpper << std::endl;
        }

        // 2. Чтение файла (правильный путь)
        std::cout << "\n--- Test: readFile ---" << std::endl;
        std::cout << "Attempting to read file: " << fileToExtractAndTest << std::endl;
        std::vector<unsigned char> fileBuffer;
        if (mpqManager.readFile(fileToExtractAndTest, fileBuffer))
        {
            std::cout << "[SUCCESS] Read file " << fileToExtractAndTest << ", size: " << fileBuffer.size() << " bytes."
                      << std::endl;
            std::cout << "First few bytes: ";
            printBuffer(fileBuffer);
        }
        else
        {
            std::cout << "[FAILURE] Failed to read file: " << fileToExtractAndTest << std::endl;
        }

        // Попробуем прочитать (listfile)
        std::cout << "\nAttempting to read file: " << listFileInternal << std::endl;
        std::vector<unsigned char> listFileBuffer;
        if (mpqManager.readFile(listFileInternal, listFileBuffer))
        {
            std::cout << "[SUCCESS] Read file " << listFileInternal << ", size: " << listFileBuffer.size() << " bytes."
                      << std::endl;
            // Выведем (listfile) как текст, если он не слишком большой
            if (!listFileBuffer.empty() && listFileBuffer.back() != '\\0')
            {  // Добавим нуль-терминатор для безопасности
                listFileBuffer.push_back('\\0');
            }
            if (listFileBuffer.size() < 2048)
            {  // Не печатать слишком большие listfile
                std::cout << "Listfile contents: \n"
                          << reinterpret_cast<const char*>(listFileBuffer.data()) << std::endl;
            }
            else
            {
                std::cout << "Listfile is too large to print in console (" << listFileBuffer.size() << " bytes)."
                          << std::endl;
            }
        }
        else
        {
            std::cout << "[FAILURE] Failed to read file: " << listFileInternal << std::endl;
        }

        // 3. Извлечение файла
        std::cout << "\n--- Test: extractFile ---" << std::endl;
        std::cout << "Attempting to extract file: " << fileToExtractAndTest << " to " << extractedFilePath << std::endl;
        if (mpqManager.extractFile(fileToExtractAndTest, extractedFilePath))
        {
            std::cout << "[SUCCESS] Extracted file " << fileToExtractAndTest << " to " << extractedFilePath
                      << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] Failed to extract file." << std::endl;
        }

        // Попробуем извлечь (listfile)
        const std::string extractedListFilePath = "listfile_extracted.txt";
        std::cout << "\nAttempting to extract file: " << listFileInternal << " to " << extractedListFilePath
                  << std::endl;
        if (mpqManager.extractFile(listFileInternal, extractedListFilePath))
        {
            std::cout << "[SUCCESS] Extracted file " << listFileInternal << " to " << extractedListFilePath
                      << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] Failed to extract file: " << listFileInternal << std::endl;
        }

        // Закрытие архива
        std::cout << "\nClosing archive..." << std::endl;
        if (mpqManager.closeArchive())
        {
            std::cout << "[SUCCESS] Archive closed." << std::endl;
        }
        else
        {
            std::cout << "[FAILURE] Failed to close archive." << std::endl;
        }
    }
    else
    {
        std::cout << "[FAILURE] Failed to open archive: " << archivePath << std::endl;
        std::cout << "Please ensure the path is correct and the MPQ file is accessible." << std::endl;
    }

    std::cout << "\n---------------------------" << std::endl;
    std::cout << "Test finished. Press Enter to exit." << std::endl;

    // Восстанавливаем старые кодировки консоли
    SetConsoleCP(oldCp);
    SetConsoleOutputCP(oldOutCp);

    std::cin.get();  // Ожидаем нажатия Enter перед закрытием
    return 0;
}