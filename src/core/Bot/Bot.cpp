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

#include "core/Bot/Modules/OreGrindModule.h"

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
            m_gameObjectManager = new GameObjectManager(this);
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

void Bot::start(const BotStartSettings& settings)
{
    if (m_running)
    {
        qCWarning(logBot) << "Bot is already running, stop it first.";
        return;
    }

    // 1. Подготовка
    m_currentSettings = settings;
    qCInfo(logBot) << "Starting bot with module:" << static_cast<int>(m_currentSettings.activeModule);

    if (!m_btContext)
    {
        m_btContext = std::make_unique<BTContext>();
        m_btContext->character = m_character;
        m_btContext->gameObjectManager = m_gameObjectManager;
        m_btContext->movementManager = m_movementManager;
    }

    if (m_currentSettings.activeModule == ModuleType::Gathering)
    {
        m_behaviorTreeRoot = OreGrindModule::build(m_currentSettings);
    }
    else
    {
        qCCritical(logBot) << "Attempted to start with an unknown or unsupported module type.";
        m_behaviorTreeRoot.reset();
        return;
    }

    if (!m_behaviorTreeRoot)
    {
        qCCritical(logBot) << "Failed to build Behavior Tree for the selected module.";
        return;
    }

    // 2. Создание и запуск потока
    qCInfo(logBot) << "Behavior Tree built successfully. Creating and starting bot thread...";

    // Переносим всю логику создания и запуска потока сюда
    m_thread = new QThread();
    // Перемещаем сам объект Bot в этот новый поток
    this->moveToThread(m_thread);
    // Когда поток запустится, он вызовет наш слот run()
    connect(m_thread, &QThread::started, this, &Bot::run);
    // Когда мы дадим команду на выход из потока (stop()), он пошлет сигнал finished
    connect(this, &Bot::finished, m_thread, &QThread::quit);
    // Когда поток реально завершится, он сам себя удалит
    connect(m_thread, &QThread::finished, m_thread, &QObject::deleteLater);

    m_running = true;
    m_thread->start();  // ЗАПУСКАЕМ ПОТОК
}

void Bot::run()
{
    // Теперь этот метод - это просто бесконечный цикл, который выполняется в потоке
    qCInfo(logBot) << "Bot loop started in thread" << QThread::currentThreadId();

    try
    {
        while (m_running)
        {
            // 1. ОБНОВЛЯЕМ ДАННЫЕ ИЗ ИГРЫ
            SharedData dataFromDll;
            if (m_sharedMemory.read(dataFromDll))
            {
                if (m_gameObjectManager)
                {
                    m_gameObjectManager->updateFromSharedMemory(dataFromDll);
                }
                if (m_character)
                {
                    m_character->updateFromMemory();
                }
            }

            // 2. ЗАПУСКАЕМ "МОЗГ"
            if (m_behaviorTreeRoot && m_btContext)
            {
                m_behaviorTreeRoot->tick(*m_btContext);
            }

            // 3. ПАУЗА (уменьшаем, чтобы бот был отзывчивее)
            QThread::msleep(150);
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBot) << "Exception in run():" << ex.what();
    }

    qCInfo(logBot) << "Bot loop finished for PID:" << m_processId;
    // Когда цикл закончится, посылаем сигнал, что мы закончили
    emit finished();
}

void Bot::stop()
{
    if (!m_running) return;

    // Просто выставляем флаг. Цикл в run() увидит это и сам завершится.
    // Поток остановится штатно.
    qCInfo(logBot) << "Stop requested. Signalling run() loop to finish.";
    m_running = false;
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