#include "NavServiceApp.h"
#include "Communication/MessageHandler.h"
#include <QDebug>

NavServiceApp::NavServiceApp(int argc, char* argv[])
    : QObject(nullptr),
      m_app(argc, argv),
      m_loggerManager(),
      m_server(PIPE_NAME, this),  // Теперь можно передавать родителя
      m_serverThread(),           // Инициализируем поток
      m_serverMonitor(this),
      m_navMeshManager((QCoreApplication::applicationDirPath() + "/navmeshes").toStdString()),
      m_pathfinder(std::make_unique<Pathfinder>()),
      m_messageHandler(&m_navMeshManager, m_pathfinder.get(), this)
{
    qCInfo(navService) << "NavService initializing...";
    m_server.moveToThread(&m_serverThread);
    connect(&m_serverThread, &QThread::started, &m_server, &NamedPipeServer::start);
    connect(this, &NavServiceApp::destroyed, this,
            [this]()
            {
                if (m_serverThread.isRunning())
                {
                    m_server.stop();
                    m_serverThread.quit();
                    m_serverThread.wait();  // Ждем завершения потока
                }
            });
}

NavServiceApp::~NavServiceApp()
{
    qCInfo(navService) << "NavService shutting down...";
    // Остановка потока теперь происходит по сигналу destroyed,
    // но на всякий случай можно продублировать логику.
    if (m_serverThread.isRunning())
    {
        m_server.stop();                 // Говорим серверу остановиться
        m_serverThread.quit();           // Говорим потоку завершить цикл событий
        if (!m_serverThread.wait(3000))  // Ждем до 3 секунд
        {
            qCWarning(navService) << "Server thread did not stop gracefully, terminating...";
            m_serverThread.terminate();  // Принудительное завершение, если не ответил
        }
    }
}

int NavServiceApp::run()
{
    // Теперь здесь можно безопасно все запускать
    qCInfo(navService) << "Setting up connections...";
    setupConnections();

    qCInfo(navService) << "Starting server...";
    m_server.start();

    qCInfo(navService) << "NavService ready to work";
    return m_app.exec();
}

void NavServiceApp::setupConnections()
{
    // Эти соединения теперь ГАРАНТИРОВАННО межпоточные и безопасные
    connect(&m_serverMonitor, &QTimer::timeout, this, &NavServiceApp::onServerStateCheck);

    connect(&m_server, &NamedPipeServer::messageReceived, &m_messageHandler, &MessageHandler::handleRequest);
    connect(&m_messageHandler, &MessageHandler::responseReady, &m_server, &NamedPipeServer::sendResponse);

    connect(&m_server, &NamedPipeServer::clientConnected, this, &NavServiceApp::onClientConnected,
            Qt::QueuedConnection);
    connect(&m_server, &NamedPipeServer::clientDisconnected, this, &NavServiceApp::onClientDisconnected,
            Qt::QueuedConnection);
    connect(&m_server, &NamedPipeServer::errorOccurred, this, &NavServiceApp::onServerError, Qt::QueuedConnection);
}
void NavServiceApp::onServerStateCheck()
{
    if (!m_server.isRunning())
    {
        qCWarning(navService) << "Server stopped unexpectedly";
        m_app.quit();
    }
}

// Реализации слотов
void NavServiceApp::onClientConnected(quint64 clientId)
{
    qCInfo(navService) << "Client connected:" << clientId;
}

void NavServiceApp::onClientDisconnected(quint64 clientId)
{
    qCInfo(navService) << "Client disconnected:" << clientId;
}

void NavServiceApp::onServerError(DWORD errorCode, const QString& errorMessage)
{
    qCWarning(navService) << "Named Pipe error:" << errorMessage << "Code:" << errorCode;
}