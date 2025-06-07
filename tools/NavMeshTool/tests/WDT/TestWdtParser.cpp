#include "gtest/gtest.h"
#include "core/WoWFiles/Parsers/WDT/WDTParser.h"  // Относительный путь от корня проекта
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>  // Для std::filesystem::current_path
#include <iostream>    // Для std::cout, std::cin
#include <limits>      // Для std::numeric_limits

// Вспомогательная функция для чтения файла в буфер
static std::vector<char> readFileToBuffer(const std::string& fileNameInTestDataDir)
{
    // Ожидаем, что тестовые данные будут в папке "Data" рядом с исполняемым файлом теста
    std::filesystem::path dataDirPath = "Data";
    std::filesystem::path fullPath = dataDirPath / fileNameInTestDataDir;

    // Можно добавить вывод полного пути для отладки, если проблемы продолжатся
    // std::cout << "Attempting to read: " << std::filesystem::absolute(fullPath).string() << std::endl;

    std::ifstream file(fullPath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file: " + std::filesystem::absolute(fullPath).string());
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size))
    {
        throw std::runtime_error("Failed to read file: " + std::filesystem::absolute(fullPath).string());
    }
    return buffer;
}

// Тестовый класс для WDTParser
class WDTParserTest : public ::testing::Test
{
   protected:
    NavMeshTool::WDT::Parser parser;
    NavMeshTool::WDT::WDTData wdtData;

    // Здесь можно добавить SetUp() и TearDown(), если потребуется
};

// Тест на парсинг BlackTemple.wdt
TEST_F(WDTParserTest, ParseBlackTemple)
{
    std::vector<char> buffer;
    try
    {
        buffer = readFileToBuffer("BlackTemple.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read BlackTemple.wdt: " << e.what();
    }

    ASSERT_FALSE(buffer.empty()) << "BlackTemple.wdt buffer is empty.";

    wdtData.baseMapName = "BlackTemple";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(buffer.data(), buffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing BlackTemple.wdt failed.";
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for BlackTemple.wdt.";
    ASSERT_EQ(wdtData.mainEntries.size(), NavMeshTool::WDT::WDT_MAIN_ENTRIES_COUNT) << "MAIN entries count mismatch.";
    ASSERT_FALSE(wdtData.adtFileNames.empty())
        << "ADT file list should not be empty for " << wdtData.baseMapName << ".wdt";
    EXPECT_GT(wdtData.adtFileNames.size(), 0) << "Expected at least one ADT file for " << wdtData.baseMapName
                                              << ".wdt. Found: " << wdtData.adtFileNames.size();
    std::cout << "Found " << wdtData.adtFileNames.size() << " ADT files for " << wdtData.baseMapName << ".wdt"
              << std::endl;
    for (const auto& adtName : wdtData.adtFileNames)
    {
        std::cout << "  Found ADT: " << adtName << std::endl;
    }
}

// Здесь можно добавить другие тесты для других WDT файлов или специфических случаев

/*
int main(int argc, char** argv)
{
    // Инициализация Google Test
    ::testing::InitGoogleTest(&argc, argv);

    // Вывод пути для отладки, если readFileToBuffer не может найти файлы
    // std::cout << "Current Path: " << std::filesystem::current_path() << std::endl;
    // std::cout << "Attempting to access test data in: " << std::filesystem::absolute("Data/").string() << std::endl;

    // Запуск всех тестов
    int result = RUN_ALL_TESTS();

    // Опционально: Ожидание ввода пользователя перед закрытием консоли
    // std::cout << "Press ENTER to exit..." << std::endl;
    // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\\n');

    return result;
}
*/
