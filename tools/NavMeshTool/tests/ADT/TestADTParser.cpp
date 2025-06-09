#include "core/WoWFiles/Parsers/ADT/ADTParser.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>  // Для C++17 работы с файловой системой
#include <exception>   // Для std::exception
#include <cstdio>      // Для fflush

using namespace NavMeshTool::ADT;

namespace fs = std::filesystem;

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

class ADTParserTest : public ::testing::Test
{
   protected:
    // Здесь можно определить общие для всех тестов в этом наборе ресурсы
    // например, путь к директории с тестовыми данными
    std::filesystem::path testDataDir;

    void SetUp() override
    {
        try
        {
            fs::path executablePath(fs::current_path());  // Путь, откуда запущен тест
            testDataDir = (executablePath / "Data" / "ADTTestData");

            if (!fs::exists(testDataDir) || !fs::is_directory(testDataDir))
            {
                std::cerr << "[WARNING IN SETUP] Test data directory for ADT not found: " << testDataDir << std::endl;
                std::fflush(stderr);
            }
            else
            {
                std::cout << "[INFO IN SETUP] Test data directory found: " << testDataDir << std::endl;
                std::fflush(stdout);
            }
        }
        catch (const std::exception& e)
        {
            FAIL() << "Exception in SetUp: " << e.what();
        }
    }
};

TEST_F(ADTParserTest, ParseAllAdtFiles)
{
    std::vector<std::string> adtFiles;
    try
    {
        for (const auto& entry : std::filesystem::directory_iterator(testDataDir))
        {
            if (entry.is_regular_file() && entry.path().extension() == ".adt")
            {
                adtFiles.push_back(entry.path().string());
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        FAIL() << "Failed to iterate over test data directory: " << testDataDir << ". Error: " << e.what();
    }

    ASSERT_FALSE(adtFiles.empty()) << "No .adt files found in " << testDataDir;
    std::cout << "[INFO] Found " << adtFiles.size() << " ADT files to test." << std::endl;

    for (const auto& filePath : adtFiles)
    {
        std::vector<unsigned char> buffer = readFileToBuffer(filePath);
        ASSERT_FALSE(buffer.empty()) << "Buffer is empty for file: " << filePath;

        Parser parser;
        auto adtDataOpt = parser.parse(buffer, filePath);

        // Оставляем подробный вывод логов парсера, если он есть, но тест должен проходить
        ASSERT_TRUE(adtDataOpt.has_value()) << "Parsing failed for file: " << filePath;
    }
}

TEST_F(ADTParserTest, ValidateAzerothData)
{
    fs::path filePath = testDataDir / "Azeroth_28_50.adt";
    ASSERT_TRUE(fs::exists(filePath)) << "Test file does not exist: " << filePath.string();

    std::vector<unsigned char> buffer = readFileToBuffer(filePath.string());
    ASSERT_FALSE(buffer.empty()) << "Buffer is empty for file: " << filePath.string();

    Parser parser;
    auto adtDataOpt = parser.parse(buffer, filePath.string());
    ASSERT_TRUE(adtDataOpt.has_value()) << "Parsing failed for file: " << filePath.string();
    const auto& adtData = *adtDataOpt;

    // --- Проверка общей статистики по файлу ---
    // Данные из Python скрипта: total_doodad_refs = 453, total_map_obj_refs = 17
    uint32_t totalDoodadRefs = 0;
    uint32_t totalMapObjRefs = 0;
    for (const auto& chunk : adtData.mcnkChunks)
    {
        totalDoodadRefs += chunk.header.nDoodadRefs;
        totalMapObjRefs += chunk.header.nMapObjRefs;
    }
    EXPECT_EQ(totalDoodadRefs, 453) << "Mismatch in total doodad references count.";
    EXPECT_EQ(totalMapObjRefs, 17) << "Mismatch in total map object references count.";

    // --- Проверка смещений из MHDR ---
    // Данные из Python скрипта
    EXPECT_EQ(adtData.mhdr.offsetMCIN, 0x00000054);
    EXPECT_EQ(adtData.mhdr.offsetMTEX, 0x0000105C);
    EXPECT_EQ(adtData.mhdr.offsetMMDX, 0x0000125E);
    EXPECT_EQ(adtData.mhdr.offsetMMID, 0x00001F96);
    EXPECT_EQ(adtData.mhdr.offsetMWMO, 0x00002076);
    EXPECT_EQ(adtData.mhdr.offsetMWID, 0x00002170);
    EXPECT_EQ(adtData.mhdr.offsetMDDF, 0x00002184);
    EXPECT_EQ(adtData.mhdr.offsetMODF, 0x0000461C);
    EXPECT_EQ(adtData.mhdr.offsetMH2O, 0x000046E4);

    // --- Проверка MH2O ---
    ASSERT_TRUE(adtData.hasMH2O);
    // Проверяем на основе точных данных из Python-скрипта

    // MCNK_0_0 должен содержать воду
    const auto& liquid_chunk_0_0 = adtData.mh2oData.liquid_chunks[0 * 16 + 0];
    EXPECT_EQ(liquid_chunk_0_0.layer_count, 1);
    EXPECT_EQ(liquid_chunk_0_0.offset_instances, 0xC00);    // 3072
    EXPECT_EQ(liquid_chunk_0_0.offset_attributes, 0x1B60);  // 7008

    // MCNK_2_15 не должен содержать воду
    const auto& liquid_chunk_2_15 = adtData.mh2oData.liquid_chunks[2 * 16 + 15];
    EXPECT_EQ(liquid_chunk_2_15.layer_count, 0);
    EXPECT_EQ(liquid_chunk_2_15.offset_instances, 0);
    EXPECT_EQ(liquid_chunk_2_15.offset_attributes, 0);

    // --- Проверка MDDF ---
    ASSERT_EQ(adtData.mddfDefs.size(), 260);
    const auto& mddf_def_0 = adtData.mddfDefs[0];
    EXPECT_EQ(mddf_def_0.nameId, 0);
    EXPECT_EQ(mddf_def_0.uniqueId, 94578);
    EXPECT_NEAR(mddf_def_0.position.x, 15268.08f, 0.01);
    EXPECT_NEAR(mddf_def_0.position.y, 4.73f, 0.01);
    EXPECT_NEAR(mddf_def_0.position.z, 26809.13f, 0.01);

    const auto& mddf_def_last = adtData.mddfDefs.back();
    EXPECT_EQ(mddf_def_last.nameId, 46);
    EXPECT_EQ(mddf_def_last.uniqueId, 15963);
    EXPECT_NEAR(mddf_def_last.position.x, 15147.03f, 0.01);
    EXPECT_NEAR(mddf_def_last.position.y, -1.08f, 0.01);
    EXPECT_NEAR(mddf_def_last.position.z, 27024.39f, 0.01);

    // --- Проверка MODF ---
    ASSERT_EQ(adtData.modfDefs.size(), 3);
    const auto& modf_def_0 = adtData.modfDefs[0];
    EXPECT_EQ(modf_def_0.nameId, 0);
    EXPECT_EQ(modf_def_0.uniqueId, 15989);
    EXPECT_NEAR(modf_def_0.position.x, 15086.10f, 0.01);
    EXPECT_NEAR(modf_def_0.position.y, -4.89f, 0.01);
    EXPECT_NEAR(modf_def_0.position.z, 27092.02f, 0.01);

    const auto& modf_def_last = adtData.modfDefs.back();
    EXPECT_EQ(modf_def_last.nameId, 2);
    EXPECT_EQ(modf_def_last.uniqueId, 324818);
    EXPECT_NEAR(modf_def_last.position.x, 15253.71f, 0.01);
    EXPECT_NEAR(modf_def_last.position.y, 17.51f, 0.01);
    EXPECT_NEAR(modf_def_last.position.z, 26876.02f, 0.01);

    // --- Проверка путей к моделям ---
    ASSERT_EQ(adtData.doodadPaths.size(), 54);
    EXPECT_STREQ(adtData.doodadPaths[0].c_str(), "WORLD\\AZEROTH\\WESTFALL\\PASSIVEDOODADS\\TREES\\WESTFALLTREE01.M2");
    EXPECT_STREQ(adtData.doodadPaths.back().c_str(),
                 "WORLD\\AZEROTH\\WESTFALL\\PASSIVEDOODADS\\TREES\\WESTFALLTREECANOPY01.M2");

    ASSERT_EQ(adtData.wmoPaths.size(), 3);
    // Python выводит строку с лишними пробелами, уберем их для сравнения
    std::string wmo_path_0 = adtData.wmoPaths[0];
    wmo_path_0.erase(std::remove_if(wmo_path_0.begin(), wmo_path_0.end(), ::isspace), wmo_path_0.end());
    EXPECT_STREQ(
        wmo_path_0.c_str(),
        "WORLD\\WMO\\KALIMDOR\\COLLIDABLEDOODADS\\DARKSHORE\\WRECKEDELVENDESTROYER\\ELVENDESTROYERWRECKBACK.WMO");
    EXPECT_STREQ(adtData.wmoPaths.back().c_str(), "WORLD\\WMO\\DUNGEON\\MD_SHIPWRECK\\SHIPWRECK_B.WMO");

    // --- Детальная проверка MCNK чанков ---

    // [MCNK_13_6]
    // nDoodadRefs = 1, nMapObjRefs = 0, MCRF_doodad_refs = [213]
    const auto& mcnk_13_6 = adtData.mcnkChunks[13 * 16 + 6];
    EXPECT_EQ(mcnk_13_6.header.nDoodadRefs, 1);
    EXPECT_EQ(mcnk_13_6.header.nMapObjRefs, 0);
    ASSERT_TRUE(mcnk_13_6.hasMCRF);
    ASSERT_EQ(mcnk_13_6.mcrfData.doodadRefs.size(), 1);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[0], 213);
    EXPECT_TRUE(mcnk_13_6.mcrfData.mapObjectRefs.empty());

    // Проверка MCVT для MCNK 13,6
    ASSERT_TRUE(mcnk_13_6.hasMCVT);
    EXPECT_FLOAT_EQ(mcnk_13_6.mcvtData.heights[0], 0.000000f);
    EXPECT_FLOAT_EQ(mcnk_13_6.mcvtData.heights[72], 4.945577f);
    EXPECT_FLOAT_EQ(mcnk_13_6.mcvtData.heights[144], 28.976723f);

    // Проверка MCNR для MCNK 13,6
    ASSERT_TRUE(mcnk_13_6.hasMCNR);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[0].x, 26);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[0].z, 33);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[0].y, 119);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[72].x, 20);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[72].z, 35);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[72].y, 120);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[144].x, 49);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[144].z, 64);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[144].y, 97);

    // [MCNK_14_1]
    // nDoodadRefs = 0, nMapObjRefs = 0
    const auto& mcnk_14_1 = adtData.mcnkChunks[14 * 16 + 1];
    EXPECT_EQ(mcnk_14_1.header.nDoodadRefs, 0);
    EXPECT_EQ(mcnk_14_1.header.nMapObjRefs, 0);
    EXPECT_TRUE(mcnk_14_1.hasMCRF);  // MCRF может быть, но пустой
    EXPECT_TRUE(mcnk_14_1.mcrfData.doodadRefs.empty());
    EXPECT_TRUE(mcnk_14_1.mcrfData.mapObjectRefs.empty());

    // [MCNK_14_7]
    // nDoodadRefs = 3, nMapObjRefs = 0, MCRF_doodad_refs = [18, 39, 95]
    const auto& mcnk_14_7 = adtData.mcnkChunks[14 * 16 + 7];
    EXPECT_EQ(mcnk_14_7.header.nDoodadRefs, 3);
    EXPECT_EQ(mcnk_14_7.header.nMapObjRefs, 0);
    ASSERT_TRUE(mcnk_14_7.hasMCRF);
    ASSERT_EQ(mcnk_14_7.mcrfData.doodadRefs.size(), 3);
    const auto& mcnk_14_7_doodad_refs = mcnk_14_7.mcrfData.doodadRefs;
    EXPECT_THAT(mcnk_14_7_doodad_refs, testing::ElementsAre(18, 39, 95));
    EXPECT_TRUE(mcnk_14_7.mcrfData.mapObjectRefs.empty());

    // Проверка MCVT для MCNK 14,7
    ASSERT_TRUE(mcnk_14_7.hasMCVT);
    EXPECT_FLOAT_EQ(mcnk_14_7.mcvtData.heights[0], 0.000000f);
    EXPECT_FLOAT_EQ(mcnk_14_7.mcvtData.heights[72], 4.579844f);
    EXPECT_FLOAT_EQ(mcnk_14_7.mcvtData.heights[144], 4.780279f);

    // Проверка MCNR для MCNK 14,7
    ASSERT_TRUE(mcnk_14_7.hasMCNR);
    EXPECT_EQ(mcnk_14_7.mcnrData.normals[0].x, 49);
    EXPECT_EQ(mcnk_14_7.mcnrData.normals[72].z, 3);
    EXPECT_EQ(mcnk_14_7.mcnrData.normals[144].y, 126);

    // [MCNK_15_5]
    // nDoodadRefs = 1, nMapObjRefs = 0, MCRF_doodad_refs = [215]
    const auto& mcnk_15_5 = adtData.mcnkChunks[15 * 16 + 5];
    EXPECT_EQ(mcnk_15_5.header.nDoodadRefs, 1);
    EXPECT_EQ(mcnk_15_5.header.nMapObjRefs, 0);
    ASSERT_TRUE(mcnk_15_5.hasMCRF);
    ASSERT_EQ(mcnk_15_5.mcrfData.doodadRefs.size(), 1);
    EXPECT_EQ(mcnk_15_5.mcrfData.doodadRefs[0], 215);
    EXPECT_TRUE(mcnk_15_5.mcrfData.mapObjectRefs.empty());

    // Проверка MCVT для MCNK 15,5 (данные не генерировались, просто проверим наличие)
    ASSERT_TRUE(mcnk_15_5.hasMCVT);
}

TEST_F(ADTParserTest, ValidateBlackTempleData)
{
    fs::path filePath = testDataDir / "BlackTemple_28_30.adt";
    ASSERT_TRUE(fs::exists(filePath)) << "Test file does not exist: " << filePath.string();

    std::vector<unsigned char> buffer = readFileToBuffer(filePath.string());
    ASSERT_FALSE(buffer.empty()) << "Buffer is empty for file: " << filePath.string();

    Parser parser;
    auto adtDataOpt = parser.parse(buffer, filePath.string());
    ASSERT_TRUE(adtDataOpt.has_value()) << "Parsing failed for file: " << filePath.string();
    const auto& adtData = *adtDataOpt;

    // --- Общая статистика ---
    // total_doodad_refs = 0, total_map_obj_refs = 0
    uint32_t totalDoodadRefs = 0;
    uint32_t totalMapObjRefs = 0;
    for (const auto& chunk : adtData.mcnkChunks)
    {
        totalDoodadRefs += chunk.header.nDoodadRefs;
        totalMapObjRefs += chunk.header.nMapObjRefs;
    }
    EXPECT_EQ(totalDoodadRefs, 0);
    EXPECT_EQ(totalMapObjRefs, 0);

    // --- Смещения MHDR ---
    EXPECT_EQ(adtData.mhdr.offsetMCIN, 0x00000054);
    EXPECT_EQ(adtData.mhdr.offsetMTEX, 0x0000105C);
    EXPECT_EQ(adtData.mhdr.offsetMMDX, 0x0000125E);
    EXPECT_EQ(adtData.mhdr.offsetMMID, 0x00001266);
    EXPECT_EQ(adtData.mhdr.offsetMWMO, 0x0000126E);
    EXPECT_EQ(adtData.mhdr.offsetMWID, 0x00001276);
    EXPECT_EQ(adtData.mhdr.offsetMDDF, 0x0000127E);
    EXPECT_EQ(adtData.mhdr.offsetMODF, 0x00001286);

    // --- Проверка MDDF/MODF ---
    EXPECT_TRUE(adtData.mddfDefs.empty());
    EXPECT_TRUE(adtData.modfDefs.empty());

    // --- Проверка путей к моделям ---
    EXPECT_TRUE(adtData.doodadPaths.empty());
    EXPECT_TRUE(adtData.wmoPaths.empty());

    // --- Детальная проверка MCNK ---
    // В этом файле у выбранных чанков нет ссылок
    const auto& mcnk_13_6 = adtData.mcnkChunks[13 * 16 + 6];
    EXPECT_EQ(mcnk_13_6.header.nDoodadRefs, 0);
    EXPECT_EQ(mcnk_13_6.header.nMapObjRefs, 0);
}

TEST_F(ADTParserTest, ValidateExpansion01Data)
{
    fs::path filePath = testDataDir / "Expansion01_15_31.adt";
    ASSERT_TRUE(fs::exists(filePath)) << "Test file does not exist: " << filePath.string();

    std::vector<unsigned char> buffer = readFileToBuffer(filePath.string());
    ASSERT_FALSE(buffer.empty()) << "Buffer is empty for file: " << filePath.string();

    Parser parser;
    auto adtDataOpt = parser.parse(buffer, filePath.string());
    ASSERT_TRUE(adtDataOpt.has_value()) << "Parsing failed for file: " << filePath.string();
    const auto& adtData = *adtDataOpt;

    // --- Общая статистика ---
    // total_doodad_refs = 1442, total_map_obj_refs = 2
    uint32_t totalDoodadRefs = 0;
    uint32_t totalMapObjRefs = 0;
    for (const auto& chunk : adtData.mcnkChunks)
    {
        totalDoodadRefs += chunk.header.nDoodadRefs;
        totalMapObjRefs += chunk.header.nMapObjRefs;
    }
    EXPECT_EQ(totalDoodadRefs, 1442);
    EXPECT_EQ(totalMapObjRefs, 2);

    // --- Смещения MHDR ---
    EXPECT_EQ(adtData.mhdr.offsetMCIN, 0x00000054);
    EXPECT_EQ(adtData.mhdr.offsetMDDF, 0x00002539);
    EXPECT_EQ(adtData.mhdr.offsetMODF, 0x00007425);
    EXPECT_EQ(adtData.mhdr.offsetMFBO, 0x001D873D);

    // --- Проверка MDDF ---
    ASSERT_EQ(adtData.mddfDefs.size(), 561);
    const auto& mddf_def_exp01_0 = adtData.mddfDefs[0];
    EXPECT_EQ(mddf_def_exp01_0.nameId, 1);
    EXPECT_EQ(mddf_def_exp01_0.uniqueId, 944657);
    EXPECT_NEAR(mddf_def_exp01_0.position.x, 8289.66f, 0.01);

    const auto& mddf_def_exp01_last = adtData.mddfDefs.back();
    EXPECT_EQ(mddf_def_exp01_last.nameId, 59);
    EXPECT_EQ(mddf_def_exp01_last.uniqueId, 927581);
    EXPECT_NEAR(mddf_def_exp01_last.position.y, 18.72f, 0.01);

    // --- Проверка MODF ---
    ASSERT_EQ(adtData.modfDefs.size(), 1);
    const auto& modf_def_exp01_0 = adtData.modfDefs[0];
    EXPECT_EQ(modf_def_exp01_0.nameId, 0);
    EXPECT_EQ(modf_def_exp01_0.uniqueId, 920624);
    EXPECT_NEAR(modf_def_exp01_0.position.z, 16846.75f, 0.01);

    // --- Проверка путей к моделям ---
    ASSERT_EQ(adtData.doodadPaths.size(), 70);
    EXPECT_STREQ(adtData.doodadPaths[0].c_str(), "WORLD\\EXPANSION01\\DOODADS\\ZANGAR\\MUSHROOM\\ZANGARMUSHROOM05.M2");
    EXPECT_STREQ(adtData.doodadPaths.back().c_str(),
                 "WORLD\\EXPANSION01\\DOODADS\\ZANGAR\\FLOATINGSPORE\\ZM_BIG_SPORE_ANIM_01.M2");

    ASSERT_EQ(adtData.wmoPaths.size(), 1);
    EXPECT_STREQ(adtData.wmoPaths[0].c_str(), "WORLD\\WMO\\OUTLAND\\SPOREBUILDINGS\\SPOREHUT_01.WMO");

    // --- Детальная проверка MCNK ---
    const auto& mcnk_13_6 = adtData.mcnkChunks[13 * 16 + 6];
    EXPECT_EQ(mcnk_13_6.header.nDoodadRefs, 5);
    ASSERT_EQ(mcnk_13_6.mcrfData.doodadRefs.size(), 5);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[0], 54);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[1], 112);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[2], 277);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[3], 495);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[4], 496);

    const auto& mcnk_14_7 = adtData.mcnkChunks[14 * 16 + 7];
    EXPECT_EQ(mcnk_14_7.header.nDoodadRefs, 8);
    ASSERT_EQ(mcnk_14_7.mcrfData.doodadRefs.size(), 8);
    EXPECT_EQ(mcnk_14_7.mcrfData.doodadRefs[4], 185);
    EXPECT_EQ(mcnk_14_7.mcrfData.doodadRefs[7], 554);
}

TEST_F(ADTParserTest, ValidateIcecrownCitadelData)
{
    fs::path filePath = testDataDir / "IcecrownCitadel_30_30.adt";
    ASSERT_TRUE(fs::exists(filePath)) << "Test file does not exist: " << filePath.string();

    std::vector<unsigned char> buffer = readFileToBuffer(filePath.string());
    ASSERT_FALSE(buffer.empty()) << "Buffer is empty for file: " << filePath.string();

    Parser parser;
    auto adtDataOpt = parser.parse(buffer, filePath.string());
    ASSERT_TRUE(adtDataOpt.has_value()) << "Parsing failed for file: " << filePath.string();
    const auto& adtData = *adtDataOpt;

    // --- Общая статистика ---
    // total_doodad_refs = 0, total_map_obj_refs = 0
    uint32_t totalDoodadRefs = 0;
    uint32_t totalMapObjRefs = 0;
    for (const auto& chunk : adtData.mcnkChunks)
    {
        totalDoodadRefs += chunk.header.nDoodadRefs;
        totalMapObjRefs += chunk.header.nMapObjRefs;
    }
    EXPECT_EQ(totalDoodadRefs, 0);
    EXPECT_EQ(totalMapObjRefs, 0);

    // --- Смещения MHDR ---
    EXPECT_EQ(adtData.mhdr.offsetMFBO, 0x0017459B);

    // --- Проверка MDDF/MODF ---
    EXPECT_TRUE(adtData.mddfDefs.empty());
    EXPECT_TRUE(adtData.modfDefs.empty());

    // --- Проверка путей к моделям ---
    EXPECT_TRUE(adtData.doodadPaths.empty());
    EXPECT_TRUE(adtData.wmoPaths.empty());

    // --- Детальная проверка MCNK ---
    const auto& mcnk_15_5 = adtData.mcnkChunks[15 * 16 + 5];
    EXPECT_EQ(mcnk_15_5.header.nDoodadRefs, 0);
    EXPECT_EQ(mcnk_15_5.header.nMapObjRefs, 0);
}

TEST_F(ADTParserTest, ValidateNorthrendData)
{
    fs::path filePath = testDataDir / "Northrend_17_23.adt";
    ASSERT_TRUE(fs::exists(filePath)) << "Test file does not exist: " << filePath.string();

    std::vector<unsigned char> buffer = readFileToBuffer(filePath.string());
    ASSERT_FALSE(buffer.empty()) << "Buffer is empty for file: " << filePath.string();

    Parser parser;
    auto adtDataOpt = parser.parse(buffer, filePath.string());
    ASSERT_TRUE(adtDataOpt.has_value()) << "Parsing failed for file: " << filePath.string();
    const auto& adtData = *adtDataOpt;

    // --- Общая статистика ---
    // total_doodad_refs = 1831, total_map_obj_refs = 0
    uint32_t totalDoodadRefs = 0;
    uint32_t totalMapObjRefs = 0;
    for (const auto& chunk : adtData.mcnkChunks)
    {
        totalDoodadRefs += chunk.header.nDoodadRefs;
        totalMapObjRefs += chunk.header.nMapObjRefs;
    }
    EXPECT_EQ(totalDoodadRefs, 1831);
    EXPECT_EQ(totalMapObjRefs, 0);

    // --- Проверка MDDF/MODF ---
    ASSERT_EQ(adtData.mddfDefs.size(), 1157);
    EXPECT_TRUE(adtData.modfDefs.empty());

    // --- Проверка путей к моделям ---
    ASSERT_EQ(adtData.doodadPaths.size(), 12);
    EXPECT_STREQ(adtData.doodadPaths[0].c_str(),
                 "WORLD\\KALIMDOR\\AZSHARA\\SEAPLANTS\\STARFISH01_02\\STARFISH01_02.M2");
    EXPECT_STREQ(adtData.doodadPaths.back().c_str(), "WORLD\\EXPANSION02\\DOODADS\\COLDARRA\\COLDARRALOCUS.M2");
    EXPECT_TRUE(adtData.wmoPaths.empty());

    // --- Детальная проверка MCNK ---
    const auto& mcnk_14_1 = adtData.mcnkChunks[14 * 16 + 1];
    EXPECT_EQ(mcnk_14_1.header.nDoodadRefs, 6);
    ASSERT_EQ(mcnk_14_1.mcrfData.doodadRefs.size(), 6);
    EXPECT_EQ(mcnk_14_1.mcrfData.doodadRefs[0], 1);
    EXPECT_EQ(mcnk_14_1.mcrfData.doodadRefs[5], 182);
}

TEST_F(ADTParserTest, ValidateTanarisInstanceData)
{
    fs::path filePath = testDataDir / "TanarisInstance_29_30.adt";
    ASSERT_TRUE(fs::exists(filePath)) << "Test file does not exist: " << filePath.string();

    std::vector<unsigned char> buffer = readFileToBuffer(filePath.string());
    ASSERT_FALSE(buffer.empty()) << "Buffer is empty for file: " << filePath.string();

    Parser parser;
    auto adtDataOpt = parser.parse(buffer, filePath.string());
    ASSERT_TRUE(adtDataOpt.has_value()) << "Parsing failed for file: " << filePath.string();
    const auto& adtData = *adtDataOpt;

    // --- Общая статистика ---
    // total_doodad_refs = 359, total_map_obj_refs = 0
    uint32_t totalDoodadRefs = 0;
    uint32_t totalMapObjRefs = 0;
    for (const auto& chunk : adtData.mcnkChunks)
    {
        totalDoodadRefs += chunk.header.nDoodadRefs;
        totalMapObjRefs += chunk.header.nMapObjRefs;
    }
    EXPECT_EQ(totalDoodadRefs, 359);
    EXPECT_EQ(totalMapObjRefs, 0);

    // --- Проверка MDDF/MODF ---
    ASSERT_EQ(adtData.mddfDefs.size(), 64);
    EXPECT_TRUE(adtData.modfDefs.empty());

    // --- Проверка путей к моделям ---
    ASSERT_EQ(adtData.doodadPaths.size(), 19);
    EXPECT_STREQ(adtData.doodadPaths[0].c_str(), "WORLD\\KALIMDOR\\FERALAS\\PASSIVEDOODADS\\TREE\\FERALASTREE03.M2");
    EXPECT_STREQ(adtData.doodadPaths.back().c_str(), "WORLD\\KALIMDOR\\UNGORO\\PASSIVEDOODADS\\ROCKS\\UNGOROROCK06.M2");
    EXPECT_TRUE(adtData.wmoPaths.empty());

    // --- Детальная проверка MCNK ---
    const auto& mcnk_13_6 = adtData.mcnkChunks[13 * 16 + 6];
    EXPECT_EQ(mcnk_13_6.header.nDoodadRefs, 3);
    ASSERT_EQ(mcnk_13_6.mcrfData.doodadRefs.size(), 3);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[0], 41);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[1], 42);
    EXPECT_EQ(mcnk_13_6.mcrfData.doodadRefs[2], 62);

    // Проверка MCVT для MCNK 13,6
    ASSERT_TRUE(mcnk_13_6.hasMCVT);
    EXPECT_FLOAT_EQ(mcnk_13_6.mcvtData.heights[0], 0.000000f);
    EXPECT_FLOAT_EQ(mcnk_13_6.mcvtData.heights[72], 5.355225f);
    EXPECT_FLOAT_EQ(mcnk_13_6.mcvtData.heights[144], -0.624481f);

    // Проверка MCNR для MCNK 13,6
    ASSERT_TRUE(mcnk_13_6.hasMCNR);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[0].x, -11);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[72].z, 55);
    EXPECT_EQ(mcnk_13_6.mcnrData.normals[144].y, 106);

    const auto& mcnk_14_1 = adtData.mcnkChunks[14 * 16 + 1];
    EXPECT_EQ(mcnk_14_1.header.nDoodadRefs, 6);
    ASSERT_EQ(mcnk_14_1.mcrfData.doodadRefs.size(), 6);
    EXPECT_EQ(mcnk_14_1.mcrfData.doodadRefs[0], 2);
    EXPECT_EQ(mcnk_14_1.mcrfData.doodadRefs[5], 59);

    const auto& mcnk_15_5 = adtData.mcnkChunks[15 * 16 + 5];
    EXPECT_EQ(mcnk_15_5.header.nDoodadRefs, 3);
    ASSERT_EQ(mcnk_15_5.mcrfData.doodadRefs.size(), 3);
    EXPECT_EQ(mcnk_15_5.mcrfData.doodadRefs[2], 63);
}

// Точка входа main для тестов уже есть в tools/NavMeshTool/tests/main.cpp
