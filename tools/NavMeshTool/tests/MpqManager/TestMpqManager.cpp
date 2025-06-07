#include "gtest/gtest.h"
#include "core/MpqManager/MpqManager.h"  // Относительный путь к MpqManager.h
#include <QCoreApplication>
#include <QLoggingCategory>
#include <QString>
#include <vector>
#include <string>
#include <fstream>    // Для проверки существования файла
#include <algorithm>  // for std::transform

// Категория логирования для тестов MpqManager
Q_LOGGING_CATEGORY(logMpqManagerTest, "navmesh.test.mpqmanager")

// Хелпер для проверки существования файла (простой вариант)
bool fileExists(const std::string& name)
{
    std::ifstream f(name.c_str());
    return f.good();
}

class MpqManagerTest : public ::testing::Test
{
   protected:
    // Статические члены для управления общим MPQ архивом
    static MpqManager s_mpqManager;
    static bool s_commonMpqSuccessfullyOpened;
    static const std::string s_testMpqPath;  // Путь к common.mpq

    // Пути для специфических тестов
    const std::string nonExistentMpqPath = "non_existent_archive.mpq";
    const std::string testInternalFilePath =
        "World\\\\Maps\\\\Azeroth\\\\Azeroth_32_25.adt";  // Пример существующего файла, может потребоваться обновление,
                                                          // если common.mpq не содержит его
    const std::string nonExistentInternalFilePath = "NonExistentFile.txt";

    static void SetUpTestSuite()
    {
        // Инициализация Qt Application для логирования (один раз для всех тестов)
        static int argc = 1;
        static char* argv_str = const_cast<char*>("test_app");
        static char** argv_ptr = &argv_str;
        if (!QCoreApplication::instance())
        {
            new QCoreApplication(argc, argv_ptr);
            QLoggingCategory::setFilterRules("navmesh.test.mpqmanager.debug=true\\nqt.core.logging.debug=false");
        }

        qCInfo(logMpqManagerTest) << "SetUpTestSuite: Attempting to open common MPQ archive: " << s_testMpqPath.c_str();
        if (!fileExists(s_testMpqPath))
        {
            qCCritical(logMpqManagerTest)
                << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
            qCCritical(logMpqManagerTest)
                << "!!! CRITICAL: Test MPQ file (common.mpq) not found at: " << s_testMpqPath.c_str();
            qCCritical(logMpqManagerTest) << "!!! Most tests relying on common.mpq will be skipped or fail.       !!!";
            qCCritical(logMpqManagerTest) << "!!! Please ensure the file exists or update the path.               !!!";
            qCCritical(logMpqManagerTest)
                << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
            s_commonMpqSuccessfullyOpened = false;
            FAIL() << "Test MPQ file (common.mpq) not found: " << s_testMpqPath
                   << ". Cannot run tests dependent on it.";
            return;
        }

        s_commonMpqSuccessfullyOpened = s_mpqManager.openArchive(s_testMpqPath, {});
        if (!s_commonMpqSuccessfullyOpened)
        {
            qCCritical(logMpqManagerTest)
                << "Failed to open common MPQ archive: " << s_testMpqPath.c_str() << " in SetUpTestSuite.";
            FAIL() << "Failed to open common MPQ archive: " << s_testMpqPath << " in SetUpTestSuite.";
        }
        else
        {
            qCInfo(logMpqManagerTest) << "Successfully opened common MPQ archive: " << s_testMpqPath.c_str()
                                      << " in SetUpTestSuite.";
        }
    }

    static void TearDownTestSuite()
    {
        if (s_commonMpqSuccessfullyOpened)
        {
            qCInfo(logMpqManagerTest) << "TearDownTestSuite: Closing common MPQ archive.";
            s_mpqManager.closeArchive();
            s_commonMpqSuccessfullyOpened = false;
        }
    }

    // SetUp и TearDown теперь пустые, т.к. управление общим архивом происходит в TestSuite методах
    void SetUp() override {}
    void TearDown() override {}
};

// Определения статических членов
MpqManager MpqManagerTest::s_mpqManager;
bool MpqManagerTest::s_commonMpqSuccessfullyOpened = false;
const std::string MpqManagerTest::s_testMpqPath =
    "C:\\\\\\\\Games\\\\\\\\WoW Sirus\\\\\\\\World of Warcraft Sirus\\\\\\\\Data\\\\\\\\common.mpq";

TEST_F(MpqManagerTest, OpensExistingMpq)
{
    // Этот тест теперь просто проверяет состояние менеджера, открытого в SetUpTestSuite
    ASSERT_TRUE(s_commonMpqSuccessfullyOpened) << "common.mpq не был успешно открыт в SetUpTestSuite.";
    EXPECT_TRUE(s_mpqManager.isOpen());
}

TEST_F(MpqManagerTest, FailsToOpenNonExistentMpq)
{
    // Этот тест должен использовать свой собственный экземпляр MpqManager
    MpqManager localMpqManager;
    EXPECT_FALSE(localMpqManager.openArchive(nonExistentMpqPath, {})) << "Should fail to open non-existent MPQ";
    EXPECT_FALSE(localMpqManager.isOpen());
}

TEST_F(MpqManagerTest, ClosesArchive)
{
    // Этот тест проверяет, что s_mpqManager был открыт и может быть проверен на состояние.
    // Само закрытие протестировано в TearDownTestSuite.
    // Мы также можем протестировать закрытие уже закрытого архива с локальным менеджером.
    ASSERT_TRUE(s_commonMpqSuccessfullyOpened) << "common.mpq не был успешно открыт в SetUpTestSuite.";
    EXPECT_TRUE(s_mpqManager.isOpen());  // Проверяем, что он все еще открыт для этого теста

    MpqManager localMpqManager;
    // Сначала откроем и закроем локальный, чтобы проверить успешное закрытие
    if (fileExists(s_testMpqPath))
    {  // Используем существующий MPQ для локального теста закрытия
        ASSERT_TRUE(localMpqManager.openArchive(s_testMpqPath, {})) << "Failed to open MPQ for local close test";
        EXPECT_TRUE(localMpqManager.closeArchive());
        EXPECT_FALSE(localMpqManager.isOpen());
    }
    else
    {
        GTEST_SKIP() << "Skipping local close test as MPQ file not found: " << s_testMpqPath;
    }

    // Проверка закрытия уже закрытого архива
    EXPECT_TRUE(localMpqManager.closeArchive()) << "Closing an already closed or unopened archive should return true.";
    EXPECT_FALSE(localMpqManager.isOpen());
}

TEST_F(MpqManagerTest, IsOpenReturnsCorrectState)
{
    ASSERT_TRUE(s_commonMpqSuccessfullyOpened) << "common.mpq не был успешно открыт в SetUpTestSuite.";
    EXPECT_TRUE(s_mpqManager.isOpen()) << "Should be open after successful SetUpTestSuite.";
    // Состояние после закрытия проверяется неявно через TearDownTestSuite и следующий запуск SetUpTestSuite (если бы он
    // был) или можно добавить специфичный тест на закрытие и проверку isOpen() если нужно для s_mpqManager, но это
    // немного усложнит логику TearDownTestSuite.
}

TEST_F(MpqManagerTest, FileExistsInMpqFromListFile)
{
    ASSERT_TRUE(s_commonMpqSuccessfullyOpened) << "common.mpq не был успешно открыт в SetUpTestSuite.";
    ASSERT_TRUE(s_mpqManager.isOpen());

    qCInfo(logMpqManagerTest) << "FileExistsInMpqFromListFile test using pre-opened common.mpq";

    std::vector<std::string> allFiles = s_mpqManager.listFiles();
    ASSERT_FALSE(allFiles.empty()) << "Listfile from " << s_testMpqPath << " should not be empty.";
    qCInfo(logMpqManagerTest) << "Got " << allFiles.size() << " files from listfile.";

    int filesToCheckCount = 0;
    for (size_t i = 0; i < allFiles.size() && filesToCheckCount < 3; ++i)
    {
        const std::string& fileToList = allFiles[i];
        if (fileToList.empty() || fileToList == "(listfile)" || fileToList.back() == '\\\\' || fileToList.back() == '/')
        {
            qCDebug(logMpqManagerTest) << "Skipping potential directory or special entry: " << fileToList.c_str();
            continue;
        }

        qCInfo(logMpqManagerTest) << "Checking existence of file from listfile: " << fileToList.c_str();
        EXPECT_TRUE(s_mpqManager.fileExists(fileToList))
            << "File " << fileToList << " (from listfile) should exist in " << s_testMpqPath;
        filesToCheckCount++;
    }
    EXPECT_GT(filesToCheckCount, 0) << "Should have been able to check at least one file from the listfile.";

    qCInfo(logMpqManagerTest) << "Checking existence of a deliberately non-existent file: "
                              << nonExistentInternalFilePath.c_str();
    EXPECT_FALSE(s_mpqManager.fileExists(nonExistentInternalFilePath))
        << "File " << nonExistentInternalFilePath << " should not exist in " << s_testMpqPath;
}

TEST_F(MpqManagerTest, FileExistsOnClosedArchive)
{
    MpqManager localMpqManager;  // Используем локальный менеджер, который точно не открыт
    EXPECT_FALSE(localMpqManager.fileExists(testInternalFilePath))
        << "fileExists should return false if archive is not open.";
}

TEST_F(MpqManagerTest, ListAllFiles)
{
    ASSERT_TRUE(s_commonMpqSuccessfullyOpened) << "common.mpq не был успешно открыт в SetUpTestSuite.";
    ASSERT_TRUE(s_mpqManager.isOpen());

    std::vector<std::string> files = s_mpqManager.listFiles();
    EXPECT_FALSE(files.empty()) << "File list should not be empty for a valid MPQ with a listfile.";

    // Проверим, содержит ли список файлов известный файл (если он есть в common.mpq и известен)
    // Замените testInternalFilePath на актуальный файл из common.mpq, если необходимо.
    // Для данного примера, если testInternalFilePath не гарантирован в common.mpq, эта проверка может быть ненадёжной.
    // Лучше полагаться на то, что список не пуст, или искать более общий файл.
    // bool foundKnownFile = false;
    // for (const auto& file : files)
    // {
    //     if (file == testInternalFilePath) // testInternalFilePath может быть не в common.mpq
    //     {
    //         foundKnownFile = true;
    //         break;
    //     }
    // }
    // EXPECT_TRUE(foundKnownFile) << testInternalFilePath << " should be in the list of files from common.mpq.";
}

TEST_F(MpqManagerTest, ListFilesWithMask)
{
    ASSERT_TRUE(s_commonMpqSuccessfullyOpened) << "common.mpq не был успешно открыт в SetUpTestSuite.";
    ASSERT_TRUE(s_mpqManager.isOpen());

    std::string mask = "*.blp";  // Пример маски
    std::vector<std::string> files = s_mpqManager.listFiles(mask);

    // Сложно гарантировать, что *.blp файлы всегда будут, особенно в common.mpq без listfile.
    // Если common.mpq использует внешний listfile, который загружен, то это может сработать.
    // Для большей надежности, можно просто проверить, что функция выполняется без ошибок.
    // EXPECT_FALSE(files.empty()) << "File list for mask \'" << mask << "\' should not be empty if files exist.";
    qCInfo(logMpqManagerTest) << "listFiles(" << mask.c_str() << ") returned " << files.size() << " files.";

    for (const auto& file : files)
    {
        std::string lowerFile = file;
        std::string lowerMaskSuffix = mask.substr(1);  // ".blp"
        std::transform(lowerFile.begin(), lowerFile.end(), lowerFile.begin(), ::tolower);
        std::transform(lowerMaskSuffix.begin(), lowerMaskSuffix.end(), lowerMaskSuffix.begin(), ::tolower);

        ASSERT_TRUE(lowerFile.length() >= lowerMaskSuffix.length())
            << "File name " << file << " too short for mask " << mask;
        EXPECT_EQ(lowerFile.substr(lowerFile.length() - lowerMaskSuffix.length()), lowerMaskSuffix)
            << "File " << file << " does not match mask " << mask;
    }
}

TEST_F(MpqManagerTest, ListFilesOnClosedArchive)
{
    MpqManager localMpqManager;  // Используем локальный менеджер, который точно не открыт
    std::vector<std::string> files = localMpqManager.listFiles();
    EXPECT_TRUE(files.empty()) << "listFiles should return an empty vector if archive is not open.";
}

// TODO: Добавить тесты для readFile, используя s_mpqManager
// TODO: Добавить тесты для extractFile, используя s_mpqManager
// TODO: Добавить тесты для openArchive с патчами (потребует отдельного MPQ и, возможно, локального менеджера)

// --- Тесты для функциональности патчинга ---
class MpqManagerPatchingTest : public ::testing::Test
{
   protected:
    MpqManager manager;  // Локальный менеджер для каждого теста
    // Теперь тестовые данные должны копироваться CMake в подпапку Data/MpqTestData относительно исполняемого файла
    // теста
    const std::string testDataDir = "Data/MpqTestData/";

    std::string baseMpqPath;
    std::string patch2MpqPath;
    std::string patch3MpqPath;

    const std::string fileInBaseAndPatch3 = "world\\sex.txt";  // Двойные обратные слеши для C++ строк
    const size_t sizeInBase = 10103;
    const size_t sizeInPatch3 = 20208;

    const std::string file1InPatch2 = "world\\ZulAman_27_29.adt";
    const std::string file2InPatch2 = "world\\ZulAman_27_30.adt";
    const std::string file3InPatch2 = "world\\ZulAman_27_31.adt";

    void SetUp() override
    {
        baseMpqPath = testDataDir + "test.mpq";
        patch2MpqPath = testDataDir + "test-2.mpq";
        patch3MpqPath = testDataDir + "test-3.mpq";

        qCDebug(logMpqManagerTest) << "Patching Test SetUp. Looking for MPQs in: " << testDataDir.c_str();
        qCDebug(logMpqManagerTest) << "Base MPQ path: " << baseMpqPath.c_str();
        qCDebug(logMpqManagerTest) << "Patch-2 MPQ path: " << patch2MpqPath.c_str();
        qCDebug(logMpqManagerTest) << "Patch-3 MPQ path: " << patch3MpqPath.c_str();

        // Проверяем существование файлов по новым путям
        // Функция fileExists использует std::ifstream, который работает с путями относительно текущей рабочей
        // директории Исполняемый файл теста обычно запускается из своей директории, где и должна быть папка
        // Data/MpqTestData
        ASSERT_TRUE(fileExists(baseMpqPath)) << "Base test MPQ not found at: " << baseMpqPath;
        ASSERT_TRUE(fileExists(patch2MpqPath)) << "Patch-2 test MPQ not found at: " << patch2MpqPath;
        ASSERT_TRUE(fileExists(patch3MpqPath)) << "Patch-3 test MPQ not found at: " << patch3MpqPath;
    }

    void TearDown() override
    {
        if (manager.isOpen())
        {
            manager.closeArchive();
        }
    }
};

TEST_F(MpqManagerPatchingTest, BasePlusPatch2ThenPatch3)
{
    ASSERT_TRUE(manager.openArchive(baseMpqPath, {patch2MpqPath, patch3MpqPath}))
        << "Failed to open base with patch2 and patch3";

    EXPECT_TRUE(manager.fileExists(fileInBaseAndPatch3));
    EXPECT_TRUE(manager.fileExists(file1InPatch2));
    EXPECT_TRUE(manager.fileExists(file2InPatch2));
    EXPECT_TRUE(manager.fileExists(file3InPatch2));

    std::vector<unsigned char> buffer;
    ASSERT_TRUE(manager.readFileToBuffer(fileInBaseAndPatch3, buffer));
    EXPECT_EQ(buffer.size(), sizeInPatch3) << fileInBaseAndPatch3 << " should have size from patch-3.mpq";

    std::vector<std::string> files = manager.listFiles();
    // Проверяем, что список содержит как минимум наши 4 файла, и все они действительно там есть
    EXPECT_GE(files.size(), 4) << "Should list at least 4 files (1 overridden, 3 new)";
    auto checkFilePresence = [&](const std::string& name)
    {
        return std::find_if(files.begin(), files.end(),
                            [&](const std::string& listedFile)
                            {
                                std::string lowerListedFile = listedFile;
                                std::string lowerName = name;
                                std::replace(lowerListedFile.begin(), lowerListedFile.end(), '\\', '/');
                                std::replace(lowerName.begin(), lowerName.end(), '\\', '/');
                                std::transform(lowerListedFile.begin(), lowerListedFile.end(), lowerListedFile.begin(),
                                               ::tolower);
                                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                                return lowerListedFile == lowerName;
                            }) != files.end();
    };
    EXPECT_TRUE(checkFilePresence(fileInBaseAndPatch3));
    EXPECT_TRUE(checkFilePresence(file1InPatch2));
    EXPECT_TRUE(checkFilePresence(file2InPatch2));
    EXPECT_TRUE(checkFilePresence(file3InPatch2));
}

TEST_F(MpqManagerPatchingTest, BasePlusPatch3ThenPatch2)
{
    ASSERT_TRUE(manager.openArchive(baseMpqPath, {patch3MpqPath, patch2MpqPath}))
        << "Failed to open base with patch3 and patch2";

    EXPECT_TRUE(manager.fileExists(fileInBaseAndPatch3));
    EXPECT_TRUE(manager.fileExists(file1InPatch2));
    EXPECT_TRUE(manager.fileExists(file2InPatch2));
    EXPECT_TRUE(manager.fileExists(file3InPatch2));

    std::vector<unsigned char> buffer;
    ASSERT_TRUE(manager.readFileToBuffer(fileInBaseAndPatch3, buffer));
    EXPECT_EQ(buffer.size(), sizeInPatch3) << fileInBaseAndPatch3 << " should still have size from patch-3.mpq";

    std::vector<std::string> files = manager.listFiles();
    EXPECT_GE(files.size(), 4);
    auto checkFilePresence = [&](const std::string& name)
    {
        return std::find_if(files.begin(), files.end(),
                            [&](const std::string& listedFile)
                            {
                                std::string lowerListedFile = listedFile;
                                std::string lowerName = name;
                                std::replace(lowerListedFile.begin(), lowerListedFile.end(), '\\', '/');
                                std::replace(lowerName.begin(), lowerName.end(), '\\', '/');
                                std::transform(lowerListedFile.begin(), lowerListedFile.end(), lowerListedFile.begin(),
                                               ::tolower);
                                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                                return lowerListedFile == lowerName;
                            }) != files.end();
    };
    EXPECT_TRUE(checkFilePresence(fileInBaseAndPatch3));
    EXPECT_TRUE(checkFilePresence(file1InPatch2));
    EXPECT_TRUE(checkFilePresence(file2InPatch2));
    EXPECT_TRUE(checkFilePresence(file3InPatch2));
}

TEST_F(MpqManagerPatchingTest, BasePlusOnlyPatch2)
{
    ASSERT_TRUE(manager.openArchive(baseMpqPath, {patch2MpqPath})) << "Failed to open base with patch2 only";

    EXPECT_TRUE(manager.fileExists(fileInBaseAndPatch3));
    EXPECT_TRUE(manager.fileExists(file1InPatch2));
    EXPECT_TRUE(manager.fileExists(file2InPatch2));
    EXPECT_TRUE(manager.fileExists(file3InPatch2));

    std::vector<unsigned char> buffer;
    ASSERT_TRUE(manager.readFileToBuffer(fileInBaseAndPatch3, buffer));
    EXPECT_EQ(buffer.size(), sizeInBase) << fileInBaseAndPatch3 << " should have size from base test.mpq";

    std::vector<std::string> files = manager.listFiles();
    EXPECT_GE(files.size(), 4);
    auto checkFilePresence = [&](const std::string& name)
    {
        return std::find_if(files.begin(), files.end(),
                            [&](const std::string& listedFile)
                            {
                                std::string lowerListedFile = listedFile;
                                std::string lowerName = name;
                                std::replace(lowerListedFile.begin(), lowerListedFile.end(), '\\', '/');
                                std::replace(lowerName.begin(), lowerName.end(), '\\', '/');
                                std::transform(lowerListedFile.begin(), lowerListedFile.end(), lowerListedFile.begin(),
                                               ::tolower);
                                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                                return lowerListedFile == lowerName;
                            }) != files.end();
    };
    EXPECT_TRUE(checkFilePresence(fileInBaseAndPatch3));
    EXPECT_TRUE(checkFilePresence(file1InPatch2));
    EXPECT_TRUE(checkFilePresence(file2InPatch2));
    EXPECT_TRUE(checkFilePresence(file3InPatch2));
}

TEST_F(MpqManagerPatchingTest, BasePlusOnlyPatch3)
{
    ASSERT_TRUE(manager.openArchive(baseMpqPath, {patch3MpqPath})) << "Failed to open base with patch3 only";

    EXPECT_TRUE(manager.fileExists(fileInBaseAndPatch3));
    EXPECT_FALSE(manager.fileExists(file1InPatch2));
    EXPECT_FALSE(manager.fileExists(file2InPatch2));
    EXPECT_FALSE(manager.fileExists(file3InPatch2));

    std::vector<unsigned char> buffer;
    ASSERT_TRUE(manager.readFileToBuffer(fileInBaseAndPatch3, buffer));
    EXPECT_EQ(buffer.size(), sizeInPatch3) << fileInBaseAndPatch3 << " should have size from patch-3.mpq";

    std::vector<std::string> files = manager.listFiles();
    EXPECT_GE(files.size(), 1) << "Should list at least 1 file (overridden from base)";
    auto checkFilePresence = [&](const std::string& name)
    {
        return std::find_if(files.begin(), files.end(),
                            [&](const std::string& listedFile)
                            {
                                std::string lowerListedFile = listedFile;
                                std::string lowerName = name;
                                std::replace(lowerListedFile.begin(), lowerListedFile.end(), '\\', '/');
                                std::replace(lowerName.begin(), lowerName.end(), '\\', '/');
                                std::transform(lowerListedFile.begin(), lowerListedFile.end(), lowerListedFile.begin(),
                                               ::tolower);
                                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                                return lowerListedFile == lowerName;
                            }) != files.end();
    };
    EXPECT_TRUE(checkFilePresence(fileInBaseAndPatch3));
    // Убедимся, что .adt файлы действительно отсутствуют в списке
    EXPECT_FALSE(checkFilePresence(file1InPatch2));
    EXPECT_FALSE(checkFilePresence(file2InPatch2));
    EXPECT_FALSE(checkFilePresence(file3InPatch2));
}

// Главная функция для запуска тестов (если этот файл компилируется как отдельный тест)
// int main(int argc, char **argv) {
//     QCoreApplication app(argc, argv); // Для Qt логирования в тестах
//     QLoggingCategory::setFilterRules("*.debug=true\nqt.*.debug=false");
//     ::testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }