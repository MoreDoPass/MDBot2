#include "NamedPipeServer.h"
#include "Utils/Logger.h"
#include <QCoreApplication>

// === Блок вспомогательных функций ===
namespace
{
QString getWinErrorMessage(DWORD errorCode)
{
    if (errorCode == 0)
    {
        return "No error.";
    }
    LPWSTR buffer = nullptr;
    size_t size =
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buffer, 0, nullptr);
    QString message = QString("Unknown error (code: %1)").arg(errorCode);
    if (size > 0 && buffer)
    {
        message = QString::fromWCharArray(buffer, size).trimmed();
        LocalFree(buffer);
    }
    return QString("%1 (code: %2)").arg(message).arg(errorCode);
}
}  // namespace
// === Конец блока ===

NamedPipeServer::NamedPipeServer(const QString& pipeName, QObject* parent)
    : QObject(parent), m_pipeName(pipeName), m_isRunning(false), m_nextClientId(1)
{
    qCDebug(namedPipe) << "NamedPipeServer created for pipe:" << m_pipeName;
}

NamedPipeServer::~NamedPipeServer()
{
    // stop() должен быть вызван извне перед уничтожением,
    // но на всякий случай оставляем.
    if (isRunning())
    {
        stop();
    }
    qCDebug(namedPipe) << "NamedPipeServer destroyed.";
}

void NamedPipeServer::start()
{
    if (m_isRunning.load())
    {
        qCWarning(namedPipe) << "Server is already running.";
        return;
    }

    m_isRunning.store(true);
    emit serverStarted();  // Сигнализируем о начале работы
    qCInfo(namedPipe) << "Server loop started in thread" << QThread::currentThreadId();

    // ВЕСЬ ЦИКЛ ИЗ СТАРОГО serverLoop() ТЕПЕРЬ ЗДЕСЬ
    while (m_isRunning.load())
    {
        HANDLE hPipe = CreateNamedPipeW((const wchar_t*)m_pipeName.utf16(), PIPE_ACCESS_DUPLEX,
                                        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
                                        BUFFER_SIZE, BUFFER_SIZE, PIPE_TIMEOUT, nullptr);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            DWORD error = GetLastError();
            qCCritical(namedPipe) << "Failed to create named pipe instance:" << getWinErrorMessage(error);
            emit errorOccurred(error, getWinErrorMessage(error));
            m_isRunning.store(false);
            break;
        }

        m_hCurrentPipe.store(hPipe);
        qCDebug(namedPipe) << "Pipe instance created. Waiting for a client...";
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        m_hCurrentPipe.store(INVALID_HANDLE_VALUE);  // Сбрасываем после ConnectNamedPipe

        if (!m_isRunning.load())
        {
            CloseHandle(hPipe);
            break;  // Выходим, если пришла команда stop()
        }

        if (connected || GetLastError() == ERROR_PIPE_CONNECTED)
        {
            quint64 clientId = generateClientId();
            qCInfo(namedPipe) << "Client connected with ID:" << clientId;
            {
                QMutexLocker locker(&m_mutex);
                m_activeClients.insert(clientId, hPipe);
            }
            emit clientConnected(clientId);

            handleClient(hPipe, clientId);  // Блокирующий вызов, пока клиент не отключится

            {
                QMutexLocker locker(&m_mutex);
                m_activeClients.remove(clientId);
            }
            qCInfo(namedPipe) << "Client disconnected with ID:" << clientId;
            emit clientDisconnected(clientId);
        }
        else
        {
            // Не выводим ошибку, если это просто остановка сервера
            if (m_isRunning.load())
            {
                qCDebug(namedPipe) << "ConnectNamedPipe failed. Error:" << getWinErrorMessage(GetLastError());
            }
        }
        CloseHandle(hPipe);
    }

    qCInfo(namedPipe) << "Server loop finished.";
    emit serverStopped();
}

// <<< ИЗМЕНЕНИЕ: `stop` просто выставляет флаг и закрывает хэндл
void NamedPipeServer::stop()
{
    if (!m_isRunning.load())
    {
        return;
    }
    qCInfo(namedPipe) << "Stopping server...";
    m_isRunning.store(false);

    // Эта магия нужна, чтобы разблокировать ConnectNamedPipe, который ждет подключения
    HANDLE hPipeToCancel =
        CreateFileW((const wchar_t*)m_pipeName.utf16(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipeToCancel != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPipeToCancel);
        qCDebug(namedPipe) << "Sent dummy connection to unblock server thread.";
    }
}

bool NamedPipeServer::isRunning() const
{
    return m_isRunning.load();
}
QString NamedPipeServer::pipeName() const
{
    return m_pipeName;
}
quint64 NamedPipeServer::generateClientId()
{
    return m_nextClientId.fetch_add(1) + 1;
}

void NamedPipeServer::sendResponse(quint64 clientId, const QString& message)
{
    QMutexLocker locker(&m_mutex);  // Блокируем доступ к m_activeClients
    HANDLE hPipe = m_activeClients.value(clientId, nullptr);

    if (hPipe == nullptr)
    {
        qCWarning(namedPipe) << "Attempted to send response to disconnected or unknown client ID:" << clientId;
        return;
    }

    qCDebug(namedPipe) << "Sending response to client" << clientId << "size:" << message.toUtf8().size() << "bytes";
    if (!writeToClient(hPipe, message.toUtf8()))
    {
        qCWarning(namedPipe) << "Failed to write response to client" << clientId;
    }
}

bool NamedPipeServer::writeToClient(HANDLE hPipe, const QByteArray& data)
{
    DWORD bytesWritten = 0;
    BOOL success = WriteFile(hPipe, data.constData(), data.size(), &bytesWritten, nullptr);

    if (!success)
    {
        DWORD error = GetLastError();
        emit errorOccurred(error, getWinErrorMessage(error));
        return false;
    }
    if (bytesWritten != data.size())
    {
        qCWarning(namedPipe) << "Could not write all data to pipe. Sent" << bytesWritten << "of" << data.size();
        return false;
    }
    return true;
}

void NamedPipeServer::serverLoop()
{
    qCInfo(namedPipe) << "Server loop started in thread" << QThread::currentThreadId();
    while (m_isRunning.load())
    {
        HANDLE hPipe = CreateNamedPipeW((const wchar_t*)m_pipeName.utf16(), PIPE_ACCESS_DUPLEX,
                                        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
                                        BUFFER_SIZE, BUFFER_SIZE, PIPE_TIMEOUT, nullptr);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            DWORD error = GetLastError();
            qCCritical(namedPipe) << "Failed to create named pipe instance:" << getWinErrorMessage(error);
            emit errorOccurred(error, getWinErrorMessage(error));
            m_isRunning.store(false);
            break;
        }

        m_hCurrentPipe.store(hPipe);
        qCDebug(namedPipe) << "Pipe instance created. Waiting for a client...";
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        m_hCurrentPipe.store(INVALID_HANDLE_VALUE);

        if (!m_isRunning.load())
        {
            CloseHandle(hPipe);
            break;
        }

        if (connected || GetLastError() == ERROR_PIPE_CONNECTED)
        {
            quint64 clientId = generateClientId();
            qCInfo(namedPipe) << "Client connected with ID:" << clientId;

            {
                QMutexLocker locker(&m_mutex);
                m_activeClients.insert(clientId, hPipe);
            }
            emit clientConnected(clientId);

            handleClient(hPipe, clientId);

            {
                QMutexLocker locker(&m_mutex);
                m_activeClients.remove(clientId);
            }
            qCInfo(namedPipe) << "Client disconnected with ID:" << clientId;
            emit clientDisconnected(clientId);
        }
        else
        {
            qCDebug(namedPipe) << "ConnectNamedPipe failed, likely due to server shutdown. Error:"
                               << getWinErrorMessage(GetLastError());
        }
        CloseHandle(hPipe);
    }
    qCInfo(namedPipe) << "Server loop finished.";
}

void NamedPipeServer::handleClient(HANDLE hPipe, quint64 clientId)
{
    qCDebug(namedPipe) << "Handling client" << clientId;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead = 0;

    while (m_isRunning.load())
    {
        BOOL success = ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, nullptr);
        if (!success || bytesRead == 0)
        {
            DWORD error = GetLastError();
            if (error != ERROR_BROKEN_PIPE)
            {
                qCWarning(namedPipe) << "ReadFile failed for client" << clientId << ":" << getWinErrorMessage(error);
                emit errorOccurred(error, getWinErrorMessage(error));
            }
            break;
        }
        qCDebug(namedPipe) << "Received" << bytesRead << "bytes from client" << clientId;
        emit messageReceived(clientId, QString::fromUtf8(buffer, bytesRead));
    }
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
}