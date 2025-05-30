#include "MpqManager.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>  // Для qCDebug, qCWarning и т.д.

// Определение категории логирования (должно совпадать с Q_DECLARE_LOGGING_CATEGORY в .h)
Q_LOGGING_CATEGORY(mpqManagerLog, "core.wowfileparser.mpqmanager")

MpqManager::MpqManager(const QString& gamePath) : m_gamePath(gamePath), m_isInitialized(false)
{
    // Нормализуем путь при создании объекта, чтобы избежать проблем с двойными слешами или их отсутствием
    // m_gamePath = QDir(gamePath).canonicalPath(); // Раскомментировать, если есть подозрения на проблемы с путем
    qCInfo(mpqManagerLog) << "MpqManager created for game path:" << m_gamePath;
}

MpqManager::~MpqManager()
{
    qCInfo(mpqManagerLog) << "MpqManager destructor called. Closing archives...";
    for (const ArchiveInfo& archiveInfo : m_openedArchives)
    {
        if (archiveInfo.handle && archiveInfo.handle != INVALID_HANDLE_VALUE)
        {
            if (SFileCloseArchive(archiveInfo.handle))
            {
                // qCDebug(mpqManagerLog) << "Successfully closed archive:" << archiveInfo.name << "Handle:" <<
                // archiveInfo.handle;
            }
            else
            {
                qCWarning(mpqManagerLog) << "Failed to close archive:" << archiveInfo.name
                                         << "Handle:" << archiveInfo.handle << "Error:" << GetLastError();
            }
        }
    }
    m_openedArchives.clear();
    qCInfo(mpqManagerLog) << "All archives closed and list cleared.";
}

bool MpqManager::initialize()
{
    if (m_isInitialized)
    {
        qCInfo(mpqManagerLog) << "MpqManager already initialized.";
        return true;
    }

    qCInfo(mpqManagerLog) << "Initializing MpqManager...";
    qCDebug(mpqManagerLog) << "Raw m_gamePath at initialization start:" << m_gamePath;  // Добавлено/проверено

    // Очищаем список открытых архивов
    for (const ArchiveInfo& archiveInfo : m_openedArchives)
    {
        if (archiveInfo.handle && archiveInfo.handle != INVALID_HANDLE_VALUE) SFileCloseArchive(archiveInfo.handle);
    }
    m_openedArchives.clear();

    int archivesOpenedCount = 0;
    for (const QString& mpqBaseName : m_defaultMpqOrder)
    {
        qCDebug(mpqManagerLog) << "Processing MPQ base name:" << mpqBaseName;  // Лог для текущего mpqBaseName

        QString fullPathRoot = QDir(m_gamePath).filePath(mpqBaseName);
        QString fullPathData = QDir(m_gamePath).filePath("Data/" + mpqBaseName);
        QString pathToOpen;
        QString archiveNameToStore = mpqBaseName;

        qCDebug(mpqManagerLog) << "Attempting to locate (Data path):" << fullPathData;
        bool existsInData = QFileInfo::exists(fullPathData);
        bool isFileInData = false;
        if (existsInData)
        {
            isFileInData = QFileInfo(fullPathData).isFile();
        }
        qCDebug(mpqManagerLog) << "Exists in Data?:" << existsInData << ", IsFile in Data?:" << isFileInData;

        if (existsInData && isFileInData)
        {
            pathToOpen = fullPathData;
            qCDebug(mpqManagerLog) << "Using Data path:" << pathToOpen;
        }
        else
        {
            qCDebug(mpqManagerLog) << "Not found or not a file in Data. Attempting to locate (Root path):"
                                   << fullPathRoot;
            bool existsInRoot = QFileInfo::exists(fullPathRoot);
            bool isFileInRoot = false;
            if (existsInRoot)
            {
                isFileInRoot = QFileInfo(fullPathRoot).isFile();
            }
            qCDebug(mpqManagerLog) << "Exists in Root?:" << existsInRoot << ", IsFile in Root?:" << isFileInRoot;

            if (existsInRoot && isFileInRoot)
            {
                pathToOpen = fullPathRoot;
                qCDebug(mpqManagerLog) << "Using Root path:" << pathToOpen;
            }
        }

        if (!pathToOpen.isEmpty())
        {
            QString nativePath = QDir::toNativeSeparators(pathToOpen);

            std::wstring wstrPath = nativePath.toStdWString();
            const wchar_t* cPath = wstrPath.c_str();

            qCDebug(mpqManagerLog) << "Attempting to open with StormLib (wchar_t*):" << nativePath;

            HANDLE hArchive = nullptr;
            SetLastError(0);  // Явно сбрасываем ошибку перед вызовом StormLib
            if (SFileOpenArchive(cPath, 0, MPQ_OPEN_READ_ONLY, &hArchive))
            {
                qCInfo(mpqManagerLog) << "Successfully opened MPQ archive:" << nativePath
                                      << "Name:" << archiveNameToStore << "Handle:" << hArchive;
                m_openedArchives.prepend({hArchive, archiveNameToStore});
                archivesOpenedCount++;
            }
            else
            {
                qCWarning(mpqManagerLog) << "Failed to open MPQ archive (wchar_t*):" << nativePath
                                         << "Error Windows:" << GetLastError() << "Error errno:" << errno;
            }
        }
        else
        {
            // qCDebug(mpqManagerLog) << "MPQ archive not found (checked root and Data/):" << mpqBaseName;
        }
    }

    if (archivesOpenedCount > 0)
    {
        m_isInitialized = true;
        qCInfo(mpqManagerLog) << "MpqManager initialized successfully. Total archives opened:" << archivesOpenedCount;
    }
    else
    {
        m_isInitialized = false;
        qCWarning(mpqManagerLog) << "MpqManager initialization failed: No MPQ archives were opened from path:"
                                 << m_gamePath;
    }

    return m_isInitialized;
}

bool MpqManager::loadFile(const QString& internalFilePath, QByteArray& fileContent)
{
    if (!m_isInitialized)
    {
        qCWarning(mpqManagerLog) << "loadFile called on uninitialized MpqManager for file:" << internalFilePath;
        return false;
    }

    QString normalizedPath = internalFilePath;
    normalizedPath.replace("/", "\\");

    qCDebug(mpqManagerLog) << "loadFile: Attempting to load normalized path:" << normalizedPath;
    for (const ArchiveInfo& archiveInfo : m_openedArchives)
    {
        qCDebug(mpqManagerLog) << "loadFile: Checking in archive:" << archiveInfo.name
                               << "(Handle:" << archiveInfo.handle << ")";
        HANDLE hFileInMpq = nullptr;
        if (SFileOpenFileEx(archiveInfo.handle, normalizedPath.toStdString().c_str(), SFILE_OPEN_FROM_MPQ, &hFileInMpq))
        {
            qCDebug(mpqManagerLog) << "File" << normalizedPath << "found in archive:" << archiveInfo.name;
            DWORD dwFileSizeHigh = 0;
            DWORD dwFileSizeLow = SFileGetFileSize(hFileInMpq, &dwFileSizeHigh);

            if (dwFileSizeLow == SFILE_INVALID_SIZE || dwFileSizeLow == 0)
            {
                qCWarning(mpqManagerLog) << "File" << normalizedPath << "in archive" << archiveInfo.name
                                         << "has invalid size or is empty. SizeLow:" << dwFileSizeLow;
                SFileCloseFile(hFileInMpq);
                fileContent.clear();
                return true;
            }

            fileContent.resize(static_cast<int>(dwFileSizeLow));
            DWORD dwBytesRead = 0;

            if (SFileReadFile(hFileInMpq, fileContent.data(), dwFileSizeLow, &dwBytesRead, nullptr))
            {
                if (dwBytesRead == dwFileSizeLow)
                {
                    SFileCloseFile(hFileInMpq);
                    return true;
                }
                else
                {
                    qCWarning(mpqManagerLog)
                        << "Failed to read full file" << normalizedPath << "from archive" << archiveInfo.name
                        << ". Expected:" << dwFileSizeLow << "Read:" << dwBytesRead;
                }
            }
            else
            {
                qCWarning(mpqManagerLog) << "SFileReadFile failed for" << normalizedPath << "in archive"
                                         << archiveInfo.name << "Error:" << GetLastError();
            }
            SFileCloseFile(hFileInMpq);
            fileContent.clear();
            return false;
        }
    }
    fileContent.clear();
    return false;
}

bool MpqManager::fileExists(const QString& internalFilePath)
{
    if (!m_isInitialized)
    {
        return false;
    }

    QString normalizedPath = internalFilePath;
    normalizedPath.replace("/", "\\");

    qCDebug(mpqManagerLog) << "fileExists: Attempting to check normalized path:" << normalizedPath;
    for (const ArchiveInfo& archiveInfo : m_openedArchives)
    {
        qCDebug(mpqManagerLog) << "fileExists: Checking in archive:" << archiveInfo.name
                               << "(Handle:" << archiveInfo.handle << ")";
        HANDLE hFileInMpq = nullptr;
        if (SFileOpenFileEx(archiveInfo.handle, normalizedPath.toStdString().c_str(), SFILE_OPEN_FROM_MPQ, &hFileInMpq))
        {
            SFileCloseFile(hFileInMpq);
            qCDebug(mpqManagerLog) << "File" << normalizedPath << "exists in archive:" << archiveInfo.name;
            return true;
        }
    }
    return false;
}

bool MpqManager::isInitialized() const
{
    return m_isInitialized;
}

QList<HANDLE> MpqManager::getOpenedArchiveHandles() const
{
    if (!m_isInitialized)
    {
        qCWarning(mpqManagerLog) << "getOpenedArchiveHandles called on uninitialized MpqManager.";
        return QList<HANDLE>();
    }
    QList<HANDLE> handles;
    for (const ArchiveInfo& archiveInfo : m_openedArchives)
    {
        handles.append(archiveInfo.handle);
    }
    return handles;
}

QString MpqManager::getArchiveNameByHandle(HANDLE archiveHandle) const
{
    if (!m_isInitialized)
    {
        qCWarning(mpqManagerLog) << "getArchiveNameByHandle called on uninitialized MpqManager.";
        return QString();
    }
    for (const ArchiveInfo& archiveInfo : m_openedArchives)
    {
        if (archiveInfo.handle == archiveHandle)
        {
            return archiveInfo.name;
        }
    }
    qCWarning(mpqManagerLog) << "Archive name not found for handle:" << archiveHandle;
    return QString();
}
