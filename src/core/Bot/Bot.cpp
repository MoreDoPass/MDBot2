#include "Bot.h"
#include "core/Bot/Character/Character.h"
#include <QThread>
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logBot, "mdbot.bot")

Bot::Bot(qint64 processId, QObject* parent)
    : QObject(parent),
      m_processId(processId),
      m_memoryManager(),
      m_hookManager(&m_memoryManager),
      m_running(false),
      m_thread(nullptr)
{
    try
    {
        if (!m_memoryManager.openProcess(static_cast<DWORD>(processId)))
        {
            qCCritical(logBot) << "Не удалось открыть процесс в MemoryManager для PID:" << m_processId;
        }
        else
        {
            qCInfo(logBot) << "Создан объект Bot и MemoryManager для PID:" << m_processId;
            m_character = new Character(&m_memoryManager, this);
            m_movementManager = new MovementManager(&m_memoryManager, this);
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBot) << "Ошибка при создании Bot:" << ex.what();
    }
}

Bot::~Bot()
{
    try
    {
        qCInfo(logBot) << "Уничтожение объекта Bot для процесса с PID:" << m_processId;
        stop();
        delete m_character;
        delete m_movementManager;
        // Все ресурсы MemoryManager освободятся автоматически
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBot) << "Ошибка при уничтожении Bot:" << ex.what();
    }
    catch (...)
    {
        qCCritical(logBot) << "Неизвестная ошибка при уничтожении Bot";
    }
}

qint64 Bot::processId() const
{
    return m_processId;
}

Character* Bot::character() const
{
    return m_character;
}

MovementManager* Bot::movementManager() const
{
    return m_movementManager;
}

void Bot::run()
{
    if (m_running)
    {
        qCWarning(logBot) << "Бот уже запущен!";
        return;
    }
    m_running = true;
    if (!m_thread)
    {
        m_thread = QThread::create(
            [this]()
            {
                try
                {
                    qCInfo(logBot) << "Старт основного цикла бота для PID:" << m_processId;
                    while (m_running)
                    {
                        // Здесь основная логика бота
                        QThread::msleep(100);  // Пауза между итерациями
                    }
                    qCInfo(logBot) << "Бот завершил работу для PID:" << m_processId;
                }
                catch (const std::exception& ex)
                {
                    qCCritical(logBot) << "Ошибка в run():" << ex.what();
                }
                emit finished();
            });
        connect(m_thread, &QThread::finished, m_thread, &QObject::deleteLater);
        m_thread->start();
    }
}

void Bot::stop()
{
    if (!m_running) return;
    m_running = false;
    if (m_thread)
    {
        m_thread->quit();
        m_thread->wait();
        m_thread = nullptr;
    }
}