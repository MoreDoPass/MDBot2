#include <gtest/gtest.h>
#include "core/WoWFiles/Parsers/M2/M2Parser.h"

#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

using namespace NavMeshTool::M2;

// Вспомогательная функция для чтения файла в буфер
std::vector<unsigned char> readFileToBuffer(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        ADD_FAILURE() << "Failed to open file for reading: " << filePath;
        return {};
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
    {
        ADD_FAILURE() << "Failed to read file into buffer: " << filePath;
        return {};
    }
    return buffer;
}

// Структура для хранения наших тестовых данных
struct M2TestData
{
    std::string fileName;
    size_t expectedVertices;
    size_t expectedIndices;
    size_t expectedNormals;
};

// Используем параметризованный тест для большей наглядности результатов
class M2ParserTest : public ::testing::TestWithParam<M2TestData>
{
   protected:
    static fs::path testDataPath;

    static void SetUpTestSuite()
    {
        fs::path executablePath = fs::current_path();
        testDataPath = executablePath / "Data" / "M2TestData";
        ASSERT_TRUE(fs::exists(testDataPath) && fs::is_directory(testDataPath))
            << "Директория с тестовыми данными не найдена: " << testDataPath.string();
    }
};

std::filesystem::path M2ParserTest::testDataPath;

// =======================================================================
// ▼ СЮДА НУЖНО ВСТАВИТЬ ВЫВОД ИЗ PYTHON-СКРИПТА ▼
// =======================================================================
const std::vector<M2TestData> testCases = {
    // Формат: {"имя_файла", кол-во_вершин, кол-во_индексов, кол-во_нормалей},
    {"frostwyrm_waterfall.m2", 10, 30, 10},  {"Azjol_EggTower_01.M2", 65, 378, 126},
    {"DurotarTree01.M2", 126, 702, 234},     {"Azjol_EggSacks_01.M2", 42, 240, 80},
    {"nexus_ice_conduit_FALSE.M2", 0, 0, 0},
};
// =======================================================================
// ▲ УБЕДИТЕСЬ, ЧТО ВЫ СКОПИРОВАЛИ СЮДА АКТУАЛЬНЫЕ ДАННЫЕ ▲
// =======================================================================

TEST_P(M2ParserTest, ParseM2AndCheckCollisionGeometry)
{
    M2TestData testData = GetParam();

    fs::path filePath = testDataPath / testData.fileName;

    std::vector<unsigned char> buffer = readFileToBuffer(filePath.string());
    ASSERT_FALSE(buffer.empty()) << "Could not read file or file is empty: " << filePath.string();

    Parser parser;
    auto result = parser.parse(buffer);

    ASSERT_TRUE(result.has_value()) << "Не удалось распарсить файл: " << testData.fileName;

    if (result.has_value())
    {
        const auto& geom = result.value();

        EXPECT_EQ(geom.vertices.size(), testData.expectedVertices)
            << "Несовпадение количества вершин для файла: " << testData.fileName;
        EXPECT_EQ(geom.indices.size(), testData.expectedIndices)
            << "Несовпадение количества индексов для файла: " << testData.fileName;
        EXPECT_EQ(geom.normals.size(), testData.expectedNormals)
            << "Несовпадение количества нормалей для файла: " << testData.fileName;
    }
}

// Создаем инстансы тестов для каждого элемента в нашем векторе testCases
INSTANTIATE_TEST_SUITE_P(M2FileTests, M2ParserTest, ::testing::ValuesIn(testCases),
                         [](const testing::TestParamInfo<M2ParserTest::ParamType>& info)
                         {
                             // Создаем валидное имя для теста из имени файла
                             std::string name = info.param.fileName;
                             std::replace(name.begin(), name.end(), '.', '_');
                             return name;
                         });
