#pragma once

#include <QObject>
#include <QString>
#include <QThread>
#include <QMap>
#include <QMutex>
#include <atomic>

// Используем специальный заголовок Qt для безопасной работы с WinAPI
#include <qt_windows.h>

class NamedPipeServer : public QObject
{
    Q_OBJECT

   public:
    explicit NamedPipeServer(const QString& pipeName, QObject* parent = nullptr);
    ~NamedPipeServer();

    // Запрещаем копирование, чтобы избежать проблем
    NamedPipeServer(const NamedPipeServer&) = delete;
    NamedPipeServer& operator=(const NamedPipeServer&) = delete;

    bool isRunning() const;
    QString pipeName() const;

   public slots:
    void start();
    void stop();

    /**
     * @brief Отправляет сообщение указанному клиенту.
     * @param clientId Идентификатор клиента-получателя.
     * @param message Сообщение для отправки (предположительно JSON).
     * @note Этот слот является потокобезопасным. Его можно вызывать из любого потока.
     */
    void sendResponse(quint64 clientId, const QString& message);

   signals:
    void serverStarted();
    void serverStopped();
    void clientConnected(quint64 clientId);
    void clientDisconnected(quint64 clientId);
    void messageReceived(quint64 clientId, QString requestJson);
    void errorOccurred(DWORD errorCode, const QString& errorMessage);

   private slots:
    // Основной цикл сервера, выполняется в отдельном потоке.
    void serverLoop();

   private:
    void handleClient(HANDLE hPipe, quint64 clientId);
    bool writeToClient(HANDLE hPipe, const QByteArray& data);
    quint64 generateClientId();

    const QString m_pipeName;
    std::atomic<bool> m_isRunning;
    std::atomic<quint64> m_nextClientId;
    std::atomic<HANDLE> m_hCurrentPipe{INVALID_HANDLE_VALUE};

    // --- ДОБАВЛЕННЫЕ ПОЛЯ ---
    // Карта для хранения пар "ID клиента -> его хэндл канала"
    QMap<quint64, HANDLE> m_activeClients;
    // Мьютекс для защиты m_activeClients от одновременного доступа из разных потоков
    QMutex m_mutex;

    // Конфигурация
    static constexpr DWORD BUFFER_SIZE = 4096;
    static constexpr DWORD PIPE_TIMEOUT = 5000;
};