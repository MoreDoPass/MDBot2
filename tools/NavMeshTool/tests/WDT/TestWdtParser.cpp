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

// Тест на парсинг Karazahn.wdt
TEST_F(WDTParserTest, ParseKarazahn)
{
    std::vector<char> karazahnBuffer;
    try
    {
        karazahnBuffer = readFileToBuffer("Karazahn.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read Karazahn.wdt: " << e.what();
    }

    ASSERT_FALSE(karazahnBuffer.empty()) << "Karazahn.wdt buffer is empty.";

    wdtData.baseMapName = "Karazahn";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(karazahnBuffer.data(), karazahnBuffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing Karazahn.wdt failed.";

    // Проверяем версию MVER
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for Karazahn.wdt.";

    // Проверяем, что MPHD данные загружены (хотя бы флаги)
    // Например, EXPECT_NE(wdtData.mphd.flags, 0); // Пример, если флаги не должны быть 0

    // Проверяем, что MAIN entries были загружены
    ASSERT_EQ(wdtData.mainEntries.size(), NavMeshTool::WDT::WDT_MAIN_ENTRIES_COUNT) << "MAIN entries count mismatch.";

    // Проверяем количество и наличие ADT файлов
    ASSERT_EQ(wdtData.adtFileNames.size(), 9)
        << "Incorrect number of ADT files for Karazahn. Expected 9, got " << wdtData.adtFileNames.size();
    for (const auto& adtName : wdtData.adtFileNames)
    {
        std::cout << "Found ADT for Karazahn: " << adtName << std::endl;
    }
    // TODO: Добавить больше проверок для MPHD, MAIN, и опциональных MWMO/MODF, если они есть в Karazahn.wdt
}

// Тест на парсинг AhnQiraj.wdt
TEST_F(WDTParserTest, ParseAhnQiraj)
{
    std::vector<char> buffer;
    try
    {
        buffer = readFileToBuffer("AhnQiraj.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read AhnQiraj.wdt: " << e.what();
    }

    ASSERT_FALSE(buffer.empty()) << "AhnQiraj.wdt buffer is empty.";

    wdtData.baseMapName = "AhnQiraj";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(buffer.data(), buffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing AhnQiraj.wdt failed.";
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for AhnQiraj.wdt.";
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

// Тест на парсинг AhnQirajTemple.wdt
TEST_F(WDTParserTest, ParseAhnQirajTemple)
{
    std::vector<char> buffer;
    try
    {
        buffer = readFileToBuffer("AhnQirajTemple.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read AhnQirajTemple.wdt: " << e.what();
    }

    ASSERT_FALSE(buffer.empty()) << "AhnQirajTemple.wdt buffer is empty.";

    wdtData.baseMapName = "AhnQirajTemple";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(buffer.data(), buffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing AhnQirajTemple.wdt failed.";
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for AhnQirajTemple.wdt.";
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

// Тест на парсинг Azjol_LowerCity.wdt
TEST_F(WDTParserTest, ParseAzjolLowerCity)
{
    std::vector<char> buffer;
    try
    {
        buffer = readFileToBuffer("Azjol_LowerCity.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read Azjol_LowerCity.wdt: " << e.what();
    }

    ASSERT_FALSE(buffer.empty()) << "Azjol_LowerCity.wdt buffer is empty.";

    wdtData.baseMapName = "Azjol_LowerCity";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(buffer.data(), buffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing Azjol_LowerCity.wdt failed.";
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for Azjol_LowerCity.wdt.";
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

// Тест на парсинг Azjol_Uppercity.wdt
TEST_F(WDTParserTest, ParseAzjolUppercity)
{
    std::vector<char> buffer;
    try
    {
        buffer = readFileToBuffer("Azjol_Uppercity.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read Azjol_Uppercity.wdt: " << e.what();
    }

    ASSERT_FALSE(buffer.empty()) << "Azjol_Uppercity.wdt buffer is empty.";

    wdtData.baseMapName = "Azjol_Uppercity";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(buffer.data(), buffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing Azjol_Uppercity.wdt failed.";
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for Azjol_Uppercity.wdt.";
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

// Тест на парсинг azjolarena.wdt
TEST_F(WDTParserTest, ParseAzjolArena)
{
    std::vector<char> buffer;
    try
    {
        buffer = readFileToBuffer("azjolarena.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read azjolarena.wdt: " << e.what();
    }

    ASSERT_FALSE(buffer.empty()) << "azjolarena.wdt buffer is empty.";

    wdtData.baseMapName = "azjolarena";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(buffer.data(), buffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing azjolarena.wdt failed.";
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for azjolarena.wdt.";
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

// Тест на парсинг ExilesReachShipAlliance.wdt
TEST_F(WDTParserTest, ParseExilesReachShipAlliance)
{
    std::vector<char> buffer;
    try
    {
        buffer = readFileToBuffer("ExilesReachShipAlliance.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read ExilesReachShipAlliance.wdt: " << e.what();
    }

    ASSERT_FALSE(buffer.empty()) << "ExilesReachShipAlliance.wdt buffer is empty.";

    wdtData.baseMapName = "ExilesReachShipAlliance";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(buffer.data(), buffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing ExilesReachShipAlliance.wdt failed.";
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for ExilesReachShipAlliance.wdt.";
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

// Тест на парсинг ExilesReachShipHorde.wdt
TEST_F(WDTParserTest, ParseExilesReachShipHorde)
{
    std::vector<char> buffer;
    try
    {
        buffer = readFileToBuffer("ExilesReachShipHorde.wdt");
    }
    catch (const std::runtime_error& e)
    {
        FAIL() << "Failed to read ExilesReachShipHorde.wdt: " << e.what();
    }

    ASSERT_FALSE(buffer.empty()) << "ExilesReachShipHorde.wdt buffer is empty.";

    wdtData.baseMapName = "ExilesReachShipHorde";  // Устанавливаем имя базовой карты
    bool parseResult = parser.parse(buffer.data(), buffer.size(), wdtData);
    ASSERT_TRUE(parseResult) << "Parsing ExilesReachShipHorde.wdt failed.";
    EXPECT_EQ(wdtData.version, 18) << "MVER version mismatch for ExilesReachShipHorde.wdt.";
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

// Главная функция для запуска тестов с паузой в конце
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();  // Запускаем все тесты

    std::cout << "\nAll tests finished. Press ENTER to exit..." << std::endl;
    std::cin.clear();                                                    // Очищаем возможные флаги ошибок ввода
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Игнорируем оставшиеся символы в буфере
    std::cin.get();                                                      // Ждем нажатия Enter

    return result;  // Возвращаем результат выполнения тестов
}
