#include "appcontext.h"
#include <QLoggingCategory>
#include "core/Bot/Hooks/GetComputerNameHook.h"

// Создаем локальную категорию логирования для AppContext
Q_LOGGING_CATEGORY(logAppContext, "mdhack.appcontext")

AppContext::AppContext() = default;

AppContext::~AppContext()
{
    detach();
}

/**
 * @brief Подключается к процессу и устанавливает хуки.
 */
bool AppContext::attachToProcess(uint32_t pid, const std::wstring& processName, const QString& computerNameToSet)
{
    // Если уже были подключены, сначала отключаемся
    detach();

    try
    {
        // 1. Создаем и инициализируем MemoryManager
        m_memoryManager = std::make_unique<MemoryManager>();
        if (!m_memoryManager->openProcess(pid, processName))
        {
            qCCritical(logAppContext) << "Failed to open process with PID:" << pid;
            detach();  // Очищаем все
            return false;
        }
        m_pid = pid;
        qCInfo(logAppContext) << "Successfully attached to process" << pid;

        // 2. УСТАНОВКА ХУКА НА ИМЯ КОМПЬЮТЕРА (если оно указано)
        if (!computerNameToSet.isEmpty())
        {
            qCInfo(logAppContext) << "Attempting to set computer name via hook to:" << computerNameToSet;
            try
            {
                m_computerNameHook =
                    std::make_unique<GetComputerNameHook>(m_memoryManager.get(), computerNameToSet.toStdString());
                if (m_computerNameHook->install())
                {
                    qCInfo(logAppContext) << "GetComputerNameHook installed successfully.";
                }
                else
                {
                    qCCritical(logAppContext) << "Failed to install GetComputerNameHook.";
                    m_computerNameHook.reset();  // Очищаем, если установка не удалась
                }
            }
            catch (const std::exception& ex)
            {
                qCCritical(logAppContext) << "Failed to create GetComputerNameHook:" << ex.what();
            }
        }
        else
        {
            qCInfo(logAppContext) << "No computer name provided, skipping hook installation.";
        }

        // 3. Создаем остальные менеджеры и хуки
        m_gameObjectManager = std::make_unique<GameObjectManager>(m_memoryManager.get());
        m_hookManager = std::make_unique<HookManager>(m_memoryManager.get());
        m_playerPtrBuffer = m_memoryManager->allocMemory(sizeof(uintptr_t));
        m_teleportFlagBuffer = m_memoryManager->allocMemory(sizeof(uint8_t));

        if (!m_playerPtrBuffer || !m_teleportFlagBuffer)
        {
            qCCritical(logAppContext) << "Failed to allocate memory in target process.";
            detach();
            return false;
        }

        qCInfo(logAppContext) << "Allocated memory: PlayerPtr at" << Qt::hex
                              << reinterpret_cast<uintptr_t>(m_playerPtrBuffer);
        qCInfo(logAppContext) << "Allocated memory: TeleportFlag at" << Qt::hex
                              << reinterpret_cast<uintptr_t>(m_teleportFlagBuffer);

        const uintptr_t CHARACTER_HOOK_ADDR = 0x4FA64E;
        auto characterHook = std::make_unique<CharacterHook>(CHARACTER_HOOK_ADDR, m_memoryManager.get(),
                                                             reinterpret_cast<uintptr_t>(m_playerPtrBuffer));
        const uintptr_t TELEPORT_HOOK_ADDR = 0x7413F0;
        auto teleportHook = std::make_unique<TeleportStepFlagHook>(
            TELEPORT_HOOK_ADDR, reinterpret_cast<uintptr_t>(m_playerPtrBuffer),
            reinterpret_cast<uintptr_t>(m_teleportFlagBuffer), m_memoryManager.get());

        m_hookManager->addHook(characterHook->address(), nullptr);
        m_hookManager->addHook(teleportHook->address(), nullptr);
        characterHook->install();
        teleportHook->install();
        characterHook.release();
        teleportHook.release();

        m_teleportExecutor = std::make_unique<TeleportExecutor>(m_memoryManager.get());

        return true;
    }
    catch (const std::exception& e)
    {
        qCCritical(logAppContext) << "Exception during attachToProcess:" << e.what();
        detach();
        return false;
    }
}

/**
 * @brief Отключается от процесса и освобождает все ресурсы.
 */
void AppContext::detach()
{
    qCInfo(logAppContext) << "Detaching from process" << m_pid;

    // Снятие хука произойдет автоматически при уничтожении m_computerNameHook,
    // но для контроля порядка лучше сделать это явно.
    m_computerNameHook.reset();

    if (m_hookManager)
    {
        // m_hookManager->uninstallAll(); // Когда будет реализовано
    }
    if (m_memoryManager && m_memoryManager->isProcessOpen())
    {
        if (m_playerPtrBuffer) m_memoryManager->freeMemory(m_playerPtrBuffer);
        if (m_teleportFlagBuffer) m_memoryManager->freeMemory(m_teleportFlagBuffer);
    }
    m_teleportExecutor.reset();
    m_gameObjectManager.reset();  // <-- ДОБАВЛЕНО: очистка GOM
    m_hookManager.reset();
    m_memoryManager.reset();
    m_pid = 0;
    m_playerPtrBuffer = nullptr;
    m_teleportFlagBuffer = nullptr;
}

bool AppContext::isAttached() const
{
    return m_memoryManager && m_memoryManager->isProcessOpen();
}

uint32_t AppContext::getPid() const
{
    return m_pid;
}

TeleportExecutor* AppContext::getTeleportExecutor() const
{
    return m_teleportExecutor.get();
}

/**
 * @brief Создает объект Player на основе актуального указателя из памяти.
 */
std::optional<Player> AppContext::getPlayer()
{
    if (!m_memoryManager || !m_playerPtrBuffer)
    {
        return std::nullopt;
    }

    uintptr_t playerAddr = 0;
    if (m_memoryManager->readMemory(reinterpret_cast<uintptr_t>(m_playerPtrBuffer), playerAddr) && playerAddr != 0)
    {
        // Создаем временный объект Player, который ссылается на наш основной MemoryManager
        return Player(*m_memoryManager.get(), playerAddr);
    }

    return std::nullopt;
}

uintptr_t AppContext::getTeleportFlagBufferAddress() const
{
    return reinterpret_cast<uintptr_t>(m_teleportFlagBuffer);
}

void AppContext::updateGameObjectManager()
{
    if (m_gameObjectManager)
    {
        qCDebug(logAppContext) << "Forcing GameObjectManager update...";
        m_gameObjectManager->update();
    }
}

GameObject* AppContext::getTargetObject()
{
    if (m_gameObjectManager)
    {
        return m_gameObjectManager->getTargetObject();
    }
    return nullptr;
}