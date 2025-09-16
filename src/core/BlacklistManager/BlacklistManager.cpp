#include "BlacklistManager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDir>
#include <QCoreApplication>

Q_LOGGING_CATEGORY(logBlacklistManager, "mdbot.blacklistmanager")

BlacklistManager& BlacklistManager::instance()
{
    static BlacklistManager instance;
    return instance;
}

BlacklistManager::BlacklistManager(QObject* parent)
    : QObject(parent),
      m_stopRequested(false),
      m_filePath(
          [this]()
          {
              QDir dir(QCoreApplication::applicationDirPath());
              return dir.filePath("blacklist.json");
          }())
{
    load();
    // Запускаем наш фоновый поток при создании синглтона
    m_workerThread = std::thread(&BlacklistManager::workerLoop, this);
}

BlacklistManager::~BlacklistManager()
{
    // Корректно останавливаем фоновый поток
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_stopRequested = true;
    }
    m_cv.notify_one();  // "Будим" поток, чтобы он увидел флаг остановки
    if (m_workerThread.joinable())
    {
        m_workerThread.join();  // Ждем, пока поток завершится
    }
}

void BlacklistManager::workerLoop()
{
    qCInfo(logBlacklistManager) << "Background save thread started.";
    while (true)
    {
        QSet<quint64> guidsToSave;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            // Ждем, пока в очереди появится задание ИЛИ поступит команда на остановку
            m_cv.wait(lock, [this] { return !m_saveQueue.empty() || m_stopRequested; });

            if (m_stopRequested && m_saveQueue.empty())
            {
                // Пора завершаться, и заданий больше нет
                break;
            }

            // Забираем одно задание из очереди
            guidsToSave = m_saveQueue.front();
            m_saveQueue.pop();
        }  // Мьютекс отпускается здесь

        // Выполняем медленную операцию сохранения без блокировки
        save(guidsToSave);
    }
    qCInfo(logBlacklistManager) << "Background save thread finished.";
}

void BlacklistManager::load()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    qCInfo(logBlacklistManager) << "Loading permanent blacklist from:" << m_filePath;

    QFile file(m_filePath);
    if (!file.exists())
    {
        return;
    }
    if (!file.open(QIODevice::ReadOnly))
    {
        qCCritical(logBlacklistManager) << "Failed to open file for reading:" << file.errorString();
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (doc.isArray())
    {
        m_blacklist.clear();
        for (const QJsonValue& value : doc.array())
        {
            m_blacklist.insert(static_cast<quint64>(value.toDouble()));
        }
        qCInfo(logBlacklistManager) << "Loaded" << m_blacklist.size() << "GUIDs.";
    }
}

void BlacklistManager::save(const QSet<quint64>& guids)
{
    qCInfo(logBlacklistManager) << "Saving" << guids.size() << "GUIDs to blacklist...";
    QJsonArray array;
    for (const quint64 guid : guids)
    {
        array.append(static_cast<qint64>(guid));
    }
    QJsonDocument doc(array);
    QFile file(m_filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        qCCritical(logBlacklistManager) << "Failed to open file for writing:" << file.errorString();
        return;
    }
    file.write(doc.toJson());
    file.close();
    qCInfo(logBlacklistManager) << "Blacklist saved.";
}

void BlacklistManager::add(quint64 guid)
{
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_blacklist.contains(guid))
        {
            m_blacklist.insert(guid);
            m_saveQueue.push(m_blacklist);  // Кладем задание в очередь
            changed = true;
        }
    }

    if (changed)
    {
        qCInfo(logBlacklistManager) << "Adding GUID:" << Qt::hex << guid;
        m_cv.notify_one();  // "Будим" фоновый поток
        emit blacklistUpdated();
    }
}

void BlacklistManager::remove(quint64 guid)
{
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_blacklist.remove(guid))
        {
            m_saveQueue.push(m_blacklist);
            changed = true;
        }
    }

    if (changed)
    {
        qCInfo(logBlacklistManager) << "Removing GUID:" << Qt::hex << guid;
        m_cv.notify_one();
        emit blacklistUpdated();
    }
}

bool BlacklistManager::contains(quint64 guid) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_blacklist.contains(guid);
}

QSet<quint64> BlacklistManager::getBlacklistedGuids() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_blacklist;
}