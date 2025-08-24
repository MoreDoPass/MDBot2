#include "Bot.h"
#include "core/Bot/Character/Character.h"
#include "core/Navigation/PathfindingService.h"  // Для инициализации сервиса
#include "core/Bot/GameObjectManager/GameObjectManager.h"
#include "core/Bot/Hooks/GetComputerNameHook.h"
#include <QThread>
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logBot, "mdbot.bot")

Bot::Bot(qint64 processId, const QString& processName, const QString& computerNameToSet, QObject* parent)
    : QObject(parent),
      m_processId(processId),
      m_processName(processName),
      m_memoryManager(),
      m_hookManager(&m_memoryManager),
      m_running(false),
      m_thread(nullptr)
{
    try
    {
        if (!m_memoryManager.openProcess(static_cast<DWORD>(processId), processName.toStdWString()))
        {
            qCCritical(logBot) << "Failed to open process with MemoryManager for PID:" << m_processId;
        }
        else
        {
            qCInfo(logBot) << "Bot object and MemoryManager created for PID:" << m_processId;

            // --- УСТАНОВКА ХУКА НА ИМЯ КОМПЬЮТЕРА ---
            if (!computerNameToSet.isEmpty())
            {
                qCInfo(logBot) << "Attempting to set computer name to:" << computerNameToSet;
                m_computerNameHook =
                    std::make_unique<GetComputerNameHook>(&m_memoryManager, computerNameToSet.toStdString());
                if (m_computerNameHook->install())
                {
                    qCInfo(logBot) << "GetComputerNameHook installed successfully.";
                }
                else
                {
                    qCCritical(logBot) << "Failed to install GetComputerNameHook.";
                    m_computerNameHook.reset();  // Очищаем, если установка не удалась
                }
            }
            else
            {
                qCInfo(logBot) << "No computer name provided, skipping hook installation.";
            }

            // --- Остальная инициализация ---
            m_character = new Character(&m_memoryManager, this);
            m_movementManager = new MovementManager(&m_memoryManager, m_character, this);
            m_gameObjectManager = new GameObjectManager(&m_memoryManager, this);

            // Запускаем сервисы
            PathfindingService::getInstance().start();
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBot) << "Exception during Bot creation:" << ex.what();
    }
}

Bot::~Bot()
{
    try
    {
        qCInfo(logBot) << "Destroying Bot object for process with PID:" << m_processId;
        stop();

        // Снятие хука произойдет автоматически, когда unique_ptr m_computerNameHook будет уничтожен,
        // но лучше сделать это явно для контроля порядка.
        if (m_computerNameHook)
        {
            m_computerNameHook->uninstall();
            m_computerNameHook.reset();
            qCInfo(logBot) << "GetComputerNameHook uninstalled.";
        }

        // Останавливаем сервисы
        PathfindingService::getInstance().stop();

        delete m_gameObjectManager;
        delete m_character;
        delete m_movementManager;
        // Все ресурсы MemoryManager освободятся автоматически
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBot) << "Exception during Bot destruction:" << ex.what();
    }
    catch (...)
    {
        qCCritical(logBot) << "Unknown exception during Bot destruction";
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

GameObjectManager* Bot::gameObjectManager() const
{
    return m_gameObjectManager;
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
                        // 5. ВЫЗЫВАТЬ UPDATE В ОСНОВНОМ ЦИКЛЕ
                        if (m_character)
                        {
                            m_character->updateFromMemory();
                        }
                        if (m_gameObjectManager)
                        {
                            m_gameObjectManager->update();
                        }
                        // Здесь основная логика бота
                        QThread::msleep(1000);  // Пауза между итерациями
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
