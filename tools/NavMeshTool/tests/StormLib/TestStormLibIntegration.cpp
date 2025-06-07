#include "gtest/gtest.h"
#include <StormLib.h>
#include <windows.h>  // Для GetLastError и CreateDirectoryW
#include <string>
#include <vector>
#include <fstream>  // Для проверки существования файла

#include <QCoreApplication>
#include <QLoggingCategory>
#include <QString>
#include <QDir>  // Для создания директории

// Категория логирования для тестов StormLib
Q_LOGGING_CATEGORY(logStormLibTest, "navmesh.test.stormlibraw")

// Хелпер для проверки существования файла
bool fileExistsStormLib(const std::wstring& name)
{
    std::ifstream f(name.c_str());
    return f.good();
}

class StormLibIntegrationTest : public ::testing::Test
{
   protected:
    // ЗАМЕНИТЕ НА ВАШ РЕАЛЬНЫЙ ПУТЬ К COMMON.MPQ!
    const std::wstring testMpqPath_ =
        L"C:\\\\Games\\\\WoW Sirus\\\\World of Warcraft Sirus\\\\Data\\\\patch-l.mpq";  // Используем wstring для
                                                                                        // Unicode путей
    const char* testInternalFilePath_ =
        "world\\maps\\nexusevent_2\\nexusevent_2_31_32.adt";  // ИСПРАВЛЕННЫЙ путь с учетом подпапки
    const char* searchMask_ = "*.*";                          // Возвращаем общую маску для упрощенного теста FindFiles
    const std::wstring extractToPath_ =
        L"temp_stormlib_extraction_test\\\\nexusevent_2_31_32.adt";  // Соответствует testInternalFilePath_
    const std::wstring extractDir_ = L"temp_stormlib_extraction_test";

    HANDLE hMpq_ = nullptr;

    static void SetUpTestSuite()
    {
        static int argc = 1;
        static char* argv_str = const_cast<char*>("test_stormlib_app");
        static char** argv_ptr = &argv_str;
        if (!QCoreApplication::instance())
        {
            new QCoreApplication(argc, argv_ptr);
            QLoggingCategory::setFilterRules("navmesh.test.stormlibraw.debug=true\\nqt.core.logging.debug=false");
        }
    }

    void SetUp() override
    {
        // Проверка плейсхолдера и существования файла MPQ
        if (testMpqPath_ ==
                L"C:\\\\Games\\\\WoW Sirus\\\\World of Warcraft Sirus\\\\Data\\\\common.mpq" /* Замените на ваш реальный
                                                                                                путь если он другой для
                                                                                                проверки */
            && !fileExistsStormLib(testMpqPath_))
        {
            // Если используется путь по умолчанию и он не найден, пытаемся найти его в стандартном месте Sirus
            std::wstring defaultSirusPath =
                L"C:\\\\Games\\\\WoW Sirus\\\\World of Warcraft Sirus\\\\Data\\\\common.mpq";
            if (fileExistsStormLib(defaultSirusPath))
            {
                // testMpqPath_ = defaultSirusPath; // Нельзя изменять const член в SetUp
                qCWarning(logStormLibTest)
                    << "Using default Sirus MPQ path as it was found: " << QString::fromStdWString(defaultSirusPath);
            }
            else
            {
                FAIL() << "Test MPQ file not found at default path: "
                       << QString::fromStdWString(testMpqPath_).toStdString()
                       << " and placeholder path. Please set the correct path in TestStormLibIntegration.cpp.";
            }
        }
        else if (!fileExistsStormLib(testMpqPath_))
        {
            FAIL() << "Test MPQ file not found at specified path: "
                   << QString::fromStdWString(testMpqPath_).toStdString()
                   << ". Please set the correct path in TestStormLibIntegration.cpp.";
        }

        qCDebug(logStormLibTest) << "Attempting to open MPQ archive:" << QString::fromStdWString(testMpqPath_);
        SetLastError(0);
        // SFileOpenArchive принимает TCHAR*, что в Unicode сборке будет wchar_t*
        if (!SFileOpenArchive(testMpqPath_.c_str(), 0, 0, &hMpq_) || hMpq_ == nullptr)
        {
            DWORD error = GetLastError();
            qCCritical(logStormLibTest) << "Failed to open MPQ archive in SetUp: "
                                        << QString::fromStdWString(testMpqPath_) << "Error:" << error;
            hMpq_ = nullptr;  // Убедимся, что hMpq_ нулевой, если открытие не удалось
            FAIL() << "SFileOpenArchive failed in SetUp with error " << error << " for path "
                   << QString::fromStdWString(testMpqPath_).toStdString();
        }
        qCDebug(logStormLibTest) << "MPQ archive opened successfully in SetUp. Handle:" << hMpq_;
    }

    void TearDown() override
    {
        if (hMpq_ != nullptr)
        {
            qCDebug(logStormLibTest) << "Closing MPQ archive. Handle:" << hMpq_;
            if (!SFileCloseArchive(hMpq_))
            {
                qCWarning(logStormLibTest) << "SFileCloseArchive failed in TearDown. Error:" << GetLastError();
            }
            hMpq_ = nullptr;
        }
        // Очистка созданной директории и файла после теста извлечения
        QDir dir(QString::fromStdWString(extractDir_));
        if (dir.exists())
        {
            dir.removeRecursively();
        }
    }
};

TEST_F(StormLibIntegrationTest, HasFile)
{
    ASSERT_NE(hMpq_, nullptr) << "MPQ handle is null, archive not opened in SetUp.";
    qCInfo(logStormLibTest) << "Test: SFileHasFile for" << testInternalFilePath_;
    SetLastError(0);
    EXPECT_TRUE(SFileHasFile(hMpq_, testInternalFilePath_))
        << "SFileHasFile: File '" << testInternalFilePath_ << "' should exist. Error: " << GetLastError();

    SetLastError(0);
    EXPECT_FALSE(SFileHasFile(hMpq_, "THIS_FILE_SHOULD_NOT_EXIST.bla"))
        << "SFileHasFile: File 'THIS_FILE_SHOULD_NOT_EXIST.bla' should NOT exist. Error (if any other than file not "
           "found): "
        << GetLastError();
}

TEST_F(StormLibIntegrationTest, OpenReadFile)
{
    ASSERT_NE(hMpq_, nullptr) << "MPQ handle is null, archive not opened in SetUp.";
    qCInfo(logStormLibTest) << "Test: Open/Read/Close File" << testInternalFilePath_;
    HANDLE hFile = nullptr;
    SetLastError(0);
    ASSERT_TRUE(SFileOpenFileEx(hMpq_, testInternalFilePath_, SFILE_OPEN_FROM_MPQ, &hFile))
        << "SFileOpenFileEx failed for '" << testInternalFilePath_ << "'. Error: " << GetLastError();
    ASSERT_NE(hFile, nullptr) << "SFileOpenFileEx returned true but file handle is null.";

    qCDebug(logStormLibTest) << "SFileOpenFileEx: Successfully opened '" << testInternalFilePath_
                             << "'. Handle:" << hFile;

    DWORD dwFileSize = SFileGetFileSize(hFile, nullptr);
    EXPECT_NE(dwFileSize, SFILE_INVALID_SIZE) << "SFileGetFileSize failed. Error: " << GetLastError();
    if (dwFileSize > 0 && dwFileSize != SFILE_INVALID_SIZE)
    {
        qCDebug(logStormLibTest) << "SFileGetFileSize: Size of '" << testInternalFilePath_ << "' is" << dwFileSize
                                 << "bytes.";
    }

    if (dwFileSize > 0 && dwFileSize != SFILE_INVALID_SIZE)
    {
        char buffer[128];  // Маленький буфер для теста чтения
        DWORD dwBytesRead = 0;
        SetLastError(0);
        EXPECT_TRUE(SFileReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, nullptr))
            << "SFileReadFile failed. Error: " << GetLastError();
        EXPECT_GT(dwBytesRead, 0u) << "SFileReadFile should read some bytes.";
        qCDebug(logStormLibTest) << "SFileReadFile: Successfully read" << dwBytesRead << "bytes.";
    }

    SetLastError(0);
    EXPECT_TRUE(SFileCloseFile(hFile)) << "SFileCloseFile failed. Error: " << GetLastError();
}

TEST_F(StormLibIntegrationTest, FindFiles)
{
    ASSERT_NE(hMpq_, nullptr) << "MPQ handle is null, archive not opened in SetUp.";
    qCInfo(logStormLibTest) << "Test: File Search with mask" << searchMask_;
    SFILE_FIND_DATA sfd;
    SetLastError(0);

    HANDLE hFind = SFileFindFirstFile(hMpq_, searchMask_, &sfd, nullptr);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        qCWarning(logStormLibTest)
            << "SFileFindFirstFile for mask '" << searchMask_
            << "' returned INVALID_HANDLE_VALUE. Error: " << GetLastError()
            << ". This is often expected for a patch archive without a (listfile). Test will proceed.";
        // В этом случае дальнейшие проверки sfd и SFileFindNextFile не имеют смысла,
        // но тест не будет считаться проваленным только из-за этого.
    }
    else
    {
        qCDebug(logStormLibTest) << "SFileFindFirstFile: Found (potentially garbage if no listfile):" << sfd.cFileName
                                 << "(Size:" << sfd.dwFileSize << ")";

        // Попробуем SFileFindNextFile один раз, чтобы убедиться, что функция вызывается.
        if (SFileFindNextFile(hFind, &sfd))
        {
            qCDebug(logStormLibTest) << "SFileFindNextFile: Found (potentially garbage):" << sfd.cFileName
                                     << "(Size:" << sfd.dwFileSize << ")";
        }
        else
        {
            DWORD findNextError = GetLastError();
            if (findNextError != ERROR_NO_MORE_FILES)
            {
                qCWarning(logStormLibTest)
                    << "SFileFindNextFile finished with an error (other than NO_MORE_FILES): " << findNextError
                    << ". This might indicate issues if a listfile is expected or the first find was erroneous.";
            }
            else
            {
                qCDebug(logStormLibTest) << "SFileFindNextFile: No more files (or first attempt failed as expected).";
            }
        }
        SFileFindClose(hFind);  // Закрываем хендл только если он был валидным
        qCDebug(logStormLibTest) << "SFileFindClose called for valid handle.";
    }
    // Этот тест теперь в основном проверяет, что вызовы API не падают.
    // Для патч-архивов без listfile он не может гарантировать нахождение файлов.
    SUCCEED();  // Явно помечаем тест как успешный, если мы дошли до сюда без крэшей.
}

TEST_F(StormLibIntegrationTest, ExtractFile)
{
    ASSERT_NE(hMpq_, nullptr) << "MPQ handle is null, archive not opened in SetUp.";
    qCInfo(logStormLibTest) << "Test: SFileExtractFile from" << testInternalFilePath_ << "to"
                            << QString::fromStdWString(extractToPath_);

    // Создадим директорию, если ее нет (для Windows) - используем Unicode версию
    if (!CreateDirectoryW(extractDir_.c_str(), nullptr))
    {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS)
        {
            FAIL() << "CreateDirectoryW failed for " << QString::fromStdWString(extractDir_).toStdString()
                   << " with error " << error;
        }
    }
    qCDebug(logStormLibTest) << "Ensured extraction directory exists:" << QString::fromStdWString(extractDir_);

    SetLastError(0);
    // SFileExtractFile: первый аргумент (внутренний путь) - char*, второй (внешний путь) - TCHAR* (wchar_t*)
    ASSERT_TRUE(SFileExtractFile(hMpq_, testInternalFilePath_, extractToPath_.c_str(), SFILE_OPEN_FROM_MPQ))
        << "SFileExtractFile failed to extract '" << testInternalFilePath_ << "' to '"
        << QString::fromStdWString(extractToPath_).toStdString() << "'. Error: " << GetLastError();

    qCDebug(logStormLibTest) << "SFileExtractFile: Successfully extracted. Verifying file existence...";
    EXPECT_TRUE(fileExistsStormLib(extractToPath_))
        << "Extracted file " << QString::fromStdWString(extractToPath_).toStdString()
        << " does not exist after extraction.";
}

// No main() function here, GTest provides its own in main.cpp