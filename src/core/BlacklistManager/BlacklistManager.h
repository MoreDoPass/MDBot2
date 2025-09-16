#pragma once

#include <QObject>
#include <QSet>
#include <QString>
#include <QLoggingCategory>
#include <thread>              // <-- Чистый C++
#include <mutex>               // <-- Чистый C++
#include <condition_variable>  // <-- Чистый C++
#include <queue>               // <-- Чистый C++
#include <atomic>              // <-- Чистый C++

/**
 * @class BlacklistManager
 * @brief Потокобезопасный синглтон, использующий стандартный C++ поток для файловых операций.
 * @details Простой, надежный, без зависимостей от сложных модулей Qt.
 */
class BlacklistManager : public QObject
{
    Q_OBJECT

   public:
    static BlacklistManager& instance();

    BlacklistManager(const BlacklistManager&) = delete;
    void operator=(const BlacklistManager&) = delete;

    void add(quint64 guid);
    void remove(quint64 guid);
    bool contains(quint64 guid) const;
    QSet<quint64> getBlacklistedGuids() const;

   signals:
    void blacklistUpdated();

   private:
    explicit BlacklistManager(QObject* parent = nullptr);
    ~BlacklistManager();  // <-- Деструктор теперь важен для остановки потока

    void load();
    void save(const QSet<quint64>& guids);

    // --- Механизмы для фонового потока ---
    void workerLoop();  // Функция, которую будет выполнять наш фоновый поток

    std::thread m_workerThread;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::queue<QSet<quint64>> m_saveQueue;  // Очередь заданий на сохранение
    std::atomic<bool> m_stopRequested;      // Флаг для остановки потока

    // --- Данные ---
    QSet<quint64> m_blacklist;
    const QString m_filePath;
};

Q_DECLARE_LOGGING_CATEGORY(logBlacklistManager)