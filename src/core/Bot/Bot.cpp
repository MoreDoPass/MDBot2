#include "Bot.h"
#include "core/Bot/Character/Character.h"
#include "core/Bot/GameObjectManager/GameObjectManager.h"
#include "core/Bot/Hooks/GetComputerNameHook.h"
#include <QThread>
#include <QLoggingCategory>
#include "core/InjectionManager/InjectionManager.h"
#include <stdexcept>  // Для std::runtime_error
#include "Shared/Data/SharedData.h"
#include <stdexcept>
#include <QDebug>

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
            throw std::runtime_error("Failed to open process. Try running as an administrator.");
        }
        else
        {
            qCInfo(logBot) << "Bot object and MemoryManager created for PID:" << m_processId;

            m_sharedMemoryName = L"MDBot2_SharedBlock_" + std::to_wstring(m_processId);
            qCInfo(logBot) << "Creating shared memory block:" << QString::fromStdWString(m_sharedMemoryName);

            if (!m_sharedMemory.create(m_sharedMemoryName, sizeof(SharedData)))
            {
                qCCritical(logBot) << "Failed to create shared memory block.";
                throw std::runtime_error("Could not create shared memory block.");
            }
            qCInfo(logBot) << "Shared memory created successfully.";

            qCInfo(logBot) << "Attempting to inject MDBot_Client.dll...";
            const std::string dllName = "MDBot_Client.dll";
            uintptr_t dllBaseAddress = InjectionManager::Inject(static_cast<DWORD>(m_processId), dllName);

            if (dllBaseAddress != 0)
            {
                qCInfo(logBot) << "DLL INJECTED SUCCESSFULLY. Base address:" << Qt::hex << dllBaseAddress;
            }
            else
            {
                qCCritical(logBot) << "Failed to inject DLL into process" << m_processId;
                throw std::runtime_error(
                    "Failed to inject DLL. Ensure the file exists and MDBot2 is run as an administrator.");
            }

            m_character = new Character(&m_memoryManager, this);
            m_gameObjectManager = new GameObjectManager(&m_memoryManager, this);
            // --- КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: Передаем m_sharedMemory вместо m_memoryManager ---
            m_movementManager = new MovementManager(&m_sharedMemory, m_character, this);
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBot) << "Exception during Bot creation:" << ex.what();
        throw;
    }
}

Bot::~Bot()
{
    try
    {
        qCInfo(logBot) << "Destroying Bot object for process with PID:" << m_processId;
        stop();

        if (m_computerNameHook)
        {
            m_computerNameHook->uninstall();
            m_computerNameHook.reset();
            qCInfo(logBot) << "GetComputerNameHook uninstalled.";
        }

        delete m_gameObjectManager;
        delete m_character;
        delete m_movementManager;

        // --- 3. ОСВОБОЖДАЕМ ОБЩУЮ ПАМЯТЬ ---
        m_sharedMemory.close();
        qCInfo(logBot) << "Shared memory closed.";
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
                        SharedData dataFromDll;
                        if (m_sharedMemory.read(dataFromDll))
                        {
                            // --- КЛЮЧЕВОЕ ИЗМЕНЕНИЕ ---
                            // 1. Передаем данные в менеджеры для обновления их состояния.
                            //    Теперь Bot не занимается логикой обновления, а только делегирует ее.
                            if (m_gameObjectManager)
                            {
                                m_gameObjectManager->updateFromSharedMemory(dataFromDll);
                            }
                            if (m_character)
                            {
                                // TODO: Создать метод m_character->updateFromSharedMemory(dataFromDll.player);
                                // Пока что оставим старый метод для персонажа.
                                m_character->updateFromMemory();
                            }

                            // 2. Отправляем сигнал для GUI (например, для DebugWidget)
                            emit debugDataReady(dataFromDll);
                        }

                        // Пауза между итерациями. 200мс соответствует 5 обновлениям в секунду,
                        // как и в нашей DLL.
                        QThread::msleep(200);
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

void Bot::provideDebugData()
{
    SharedData dataFromDll;
    if (m_sharedMemory.read(dataFromDll))
    {
        // Если данные успешно прочитаны, отправляем их в GUI
        emit debugDataReady(dataFromDll);
    }
    else
    {
        qCWarning(logBot) << "Failed to read shared memory on demand for debug widget.";
    }
}