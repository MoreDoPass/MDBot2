#include <gtest/gtest.h>
#include "core/WoWFiles/Parsers/M2/M2Parser.h"

#include <QCoreApplication>
#include <QDir>
#include <string>
#include <vector>
#include <algorithm>

using namespace wow_files::m2;

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
    static std::string testDataPath;

    static void SetUpTestSuite()
    {
        QString executablePath = QCoreApplication::applicationDirPath();
        QDir executableDir(executablePath);
        testDataPath = executableDir.filePath("Data/M2TestData").toStdString();
        ASSERT_TRUE(QDir(QString::fromStdString(testDataPath)).exists())
            << "Директория с тестовыми данными не найдена: " << testDataPath;
    }
};

std::string M2ParserTest::testDataPath;

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

    std::string filePath =
        QDir(QString::fromStdString(testDataPath)).filePath(QString::fromStdString(testData.fileName)).toStdString();

    M2Parser parser;
    auto result = parser.parse(filePath);

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
