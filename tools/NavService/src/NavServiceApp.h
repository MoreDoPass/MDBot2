#pragma once
#include <QObject>
#include <QCoreApplication>
#include <memory>
#include <QTimer>
#include <QThread>  // <<< НОВОЕ

#include "Utils/Logger.h"
#include "NamedPipeServer/NamedPipeServer.h"

// === ШАГ 1.1: ДАЕМ КОМПИЛЯТОРУ ИНСТРУКЦИЮ ===
// Подключаем заголовок, чтобы NavServiceApp знал, что такое "MessageHandler"
#include "Communication/MessageHandler.h"
#include "Navigation/NavMeshManager.h"
#include "Pathfinder/Pathfinder.h"

// Вспомогательный RAII-класс для логгера
class LoggerManager
{
   public:
    LoggerManager()
    {
        Logger::initialize();
    }
    ~LoggerManager()
    {
        Logger::shutdown();
    }
};

class NavServiceApp : public QObject
{
    Q_OBJECT

   public:
    explicit NavServiceApp(int argc, char* argv[]);
    ~NavServiceApp();  // <<< НОВОЕ: Нам нужен деструктор для остановки потока

    int run();

   private slots:
    void onServerStateCheck();
    void onClientConnected(quint64 clientId);
    void onClientDisconnected(quint64 clientId);
    // Слот onMessageReceived нам больше не нужен здесь, т.к. сигнал идет напрямую в MessageHandler
    void onServerError(DWORD errorCode, const QString& errorMessage);

   private:
    void setupConnections();
    static constexpr const char* PIPE_NAME = "\\\\.\\pipe\\MyCoolNavServicePipe";

    QCoreApplication m_app;
    LoggerManager m_loggerManager;
    QThread m_serverThread;  // <<< НОВОЕ: Поток для сервера
    NamedPipeServer m_server;
    QTimer m_serverMonitor;

    // === ШАГ 1.2: ДОБАВЛЯЕМ "КОМНАТУ" В ЧЕРТЕЖ ===
    // Объявляем член класса типа MessageHandler
    NavMeshManager m_navMeshManager;
    std::unique_ptr<Pathfinder> m_pathfinder;
    MessageHandler m_messageHandler;

    static constexpr int SERVER_MONITOR_INTERVAL_MS = 1000;
};