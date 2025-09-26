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
Q_LOGGING_CATEGORY(logBT, "mdbot.bot.bt")

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

            // --- ИЗМЕНЕНИЕ 1: ПОЛУЧАЕМ УКАЗАТЕЛЬ СРАЗУ ПОСЛЕ СОЗДАНИЯ ---
            const SharedData* pSharedData = m_sharedMemory.getConstMemoryPtr();
            if (!pSharedData)
            {
                throw std::runtime_error("Failed to get a pointer to the shared memory block.");
            }

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

            // Проверяем, было ли предоставлено имя компьютера для хука.
            if (!computerNameToSet.isEmpty())
            {
                qCInfo(logBot) << "Computer name provided, attempting to install GetComputerNameHook with name:"
                               << computerNameToSet;
                try
                {
                    // Создаем хук. Его конструктор может выбросить исключение, если что-то пойдет не так.
                    m_computerNameHook =
                        std::make_unique<GetComputerNameHook>(&m_memoryManager, computerNameToSet.toStdString());

                    // Устанавливаем хук (патчим JMP в памяти целевого процесса).
                    if (m_computerNameHook->install())
                    {
                        qCInfo(logBot) << "GetComputerNameHook installed successfully.";
                    }
                    else
                    {
                        qCCritical(logBot) << "Failed to install GetComputerNameHook.";
                        m_computerNameHook.reset();  // Очищаем, т.к. хук не установился.
                        // Выбрасываем исключение, чтобы прервать создание бота, т.к. это критическая ошибка.
                        throw std::runtime_error("Failed to install GetComputerNameHook.");
                    }
                }
                catch (const std::exception& ex)
                {
                    // Ловим исключения как от конструктора, так и от нашего throw выше.
                    qCCritical(logBot) << "Failed to create or install GetComputerNameHook:" << ex.what();
                    // Перебрасываем исключение, чтобы конструктор Bot завершился с ошибкой.
                    throw;
                }
            }
            else
            {
                qCInfo(logBot) << "No computer name provided, skipping GetComputerNameHook installation.";
            }

            m_character = new Character(pSharedData, this);
            m_gameObjectManager = new GameObjectManager(pSharedData, this);
            m_movementManager =
                new MovementManager(&m_sharedMemory, &m_memoryManager, m_character, m_gameObjectManager, this);
            m_combatManager = new CombatManager(&m_sharedMemory, this);
            m_interactionManager = new InteractionManager(&m_sharedMemory, this);

            // --- НОВАЯ ЛОГИКА С ПОТОКОМ И ТАЙМЕРОМ ---
            m_thread = new QThread(this);         // Создаем поток
            m_tickTimer = new QTimer();           // Создаем таймер...
            m_tickTimer->setInterval(150);        // ...задаем ему интервал...
            m_tickTimer->moveToThread(m_thread);  // ...и перемещаем таймер в новый поток

            // Сам объект Bot тоже перемещаем в новый поток, чтобы его слоты выполнялись там
            this->moveToThread(m_thread);

            // Когда таймер сработает, будет вызван наш слот tick()
            connect(m_tickTimer, &QTimer::timeout, this, &Bot::tick);
            // Когда поток завершится, он корректно удалит таймер
            connect(m_thread, &QThread::finished, m_tickTimer, &QObject::deleteLater);

            m_thread->start();  // Запускаем поток и его цикл обработки событий
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

        // Корректно останавливаем и завершаем поток
        if (m_thread && m_thread->isRunning())
        {
            m_thread->quit();      // Говорим циклу событий завершиться
            m_thread->wait(1000);  // Ждем до 1 секунды, пока поток реально остановится
        }

        if (m_computerNameHook)
        {
            m_computerNameHook->uninstall();
            m_computerNameHook.reset();
            qCInfo(logBot) << "GetComputerNameHook uninstalled.";
        }

        delete m_gameObjectManager;
        delete m_character;
        delete m_movementManager;
        delete m_combatManager;
        delete m_interactionManager;

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

CombatManager* Bot::combatManager() const
{
    return m_combatManager;
}

InteractionManager* Bot::interactionManager() const
{
    return m_interactionManager;
}

void Bot::start(const BotStartSettings& settings, ProfileManager* profileManager)  // <-- ИЗМЕНЕНО
{
    if (m_running)
    {
        qCWarning(logBot) << "Bot is already running, stop it first.";
        return;
    }

    m_currentSettings = settings;
    qCInfo(logBot) << "Starting bot with module:" << static_cast<int>(m_currentSettings.activeModule);

    if (!m_btContext)
    {
        m_btContext = std::make_unique<BTContext>();
        m_btContext->character = m_character;
        m_btContext->gameObjectManager = m_gameObjectManager;
        m_btContext->movementManager = m_movementManager;
        m_btContext->combatManager = m_combatManager;
        m_btContext->interactionManager = m_interactionManager;
    }

    // --- ДОБАВЛЕНО: Делаем ProfileManager доступным для Дерева Поведения ---
    m_btContext->profileManager = profileManager;
    m_btContext->settings = m_currentSettings;

    if (m_currentSettings.activeModule == ModuleType::Gathering)
    {
        // Передаем в build теперь весь контекст, чтобы он мог получить доступ к настройкам
        m_behaviorTreeRoot = OreGrindModule::build(*m_btContext);
    }
    else
    {
        qCritical(logBot) << "Attempted to start with an unknown or unsupported module type.";
        m_behaviorTreeRoot.reset();
        return;
    }

    if (!m_behaviorTreeRoot)
    {
        qCCritical(logBot) << "Failed to build Behavior Tree for the selected module.";
        return;
    }

    qCInfo(logBot) << "Behavior Tree built successfully. Starting tick timer...";
    m_running = true;

    QMetaObject::invokeMethod(m_tickTimer, "start");
}

void Bot::tick()
{
    // Если флаг m_running сброшен, просто ничего не делаем.
    // Это нужно, чтобы избежать лишнего тика после вызова stop().
    if (!m_running) return;

    try
    {
        // 1. ОБНОВЛЯЕМ ДАННЫЕ ИЗ ИГРЫ
        SharedData dataFromDll;
        if (m_sharedMemory.read(dataFromDll))
        {
            SharedData* pWriteableData = m_sharedMemory.getMemoryPtr();
            if (pWriteableData && pWriteableData->commandToDll.status == CommandStatus::Acknowledged)
            {
                qCDebug(logBot) << "Acknowledged command from DLL, resetting entire command block.";
                // Мы должны очистить ВСЮ команду, чтобы любой менеджер мог отправить новую.
                pWriteableData->commandToDll.status = CommandStatus::None;
                pWriteableData->commandToDll.type = ClientCommandType::None;
                pWriteableData->commandToDll.spellId = 0;
                pWriteableData->commandToDll.targetGuid = 0;
                // Можно и позицию очистить для полной гигиены
                pWriteableData->commandToDll.position = {};
            }
        }

        // 2. ЗАПУСКАЕМ "МОЗГ"
        if (m_behaviorTreeRoot && m_btContext)
        {
            m_behaviorTreeRoot->tick(*m_btContext);
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBot) << "Exception in tick():" << ex.what();
        stop();  // Останавливаем бота в случае исключения
    }
}

void Bot::stop()
{
    if (!m_running) return;

    qCInfo(logBot) << "Stop requested. Stopping tick timer.";
    m_running = false;

    // --- ИСПРАВЛЕНИЕ: Останавливаем таймер потокобезопасно ---
    QMetaObject::invokeMethod(m_tickTimer, "stop");

    // Испускаем сигнал, чтобы GUI мог обновить свое состояние (например, кнопки).
    emit finished();
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

quint64 Bot::getCurrentTargetGuid() const
{
    // Проверяем, что контекст дерева поведения существует, чтобы избежать падения
    if (m_btContext)
    {
        // Просто возвращаем значение из контекста
        return m_btContext->currentTargetGuid;
    }

    // Если контекста нет (бот не запущен или произошла ошибка), возвращаем 0
    qCWarning(logBot) << "Attempted to get current target GUID, but BTContext is null.";
    return 0;
}