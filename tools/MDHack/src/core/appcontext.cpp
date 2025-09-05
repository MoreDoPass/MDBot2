#include "appcontext.h"
#include <QLoggingCategory>
#include "core/Bot/Hooks/GetComputerNameHook.h"
#include "shared/Structures/GameObject.h"

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
    detach();

    try
    {
        m_memoryManager = std::make_unique<MemoryManager>();
        if (!m_memoryManager->openProcess(pid, processName))
        {
            qCCritical(logAppContext) << "Failed to open process with PID:" << pid;
            detach();
            return false;
        }
        m_pid = pid;
        qCInfo(logAppContext) << "Successfully attached to process" << pid;

        if (!computerNameToSet.isEmpty())
        {
            try
            {
                m_computerNameHook =
                    std::make_unique<GetComputerNameHook>(m_memoryManager.get(), computerNameToSet.toStdString());
                if (!m_computerNameHook->install())
                {
                    qCCritical(logAppContext) << "Failed to install GetComputerNameHook.";
                    m_computerNameHook.reset();
                }
                else
                {
                    qCInfo(logAppContext) << "GetComputerNameHook installed successfully.";
                }
            }
            catch (const std::exception& ex)
            {
                qCCritical(logAppContext) << "Failed to create GetComputerNameHook:" << ex.what();
            }
        }

        m_hookManager = std::make_unique<HookManager>(m_memoryManager.get());

        m_playerPtrBuffer = m_memoryManager->allocMemory(sizeof(uintptr_t));
        m_targetPtrBuffer = m_memoryManager->allocMemory(sizeof(uintptr_t));
        m_teleportFlagBuffer = m_memoryManager->allocMemory(sizeof(uint8_t));

        if (!m_playerPtrBuffer || !m_teleportFlagBuffer || !m_targetPtrBuffer)
        {
            qCCritical(logAppContext) << "Failed to allocate memory in target process.";
            detach();
            return false;
        }

        qCInfo(logAppContext) << "Allocated memory: PlayerPtr at" << Qt::hex << m_playerPtrBuffer;
        qCInfo(logAppContext) << "Allocated memory: TargetPtr at" << Qt::hex << m_targetPtrBuffer;
        qCInfo(logAppContext) << "Allocated memory: TeleportFlag at" << Qt::hex << m_teleportFlagBuffer;

        const uintptr_t CHARACTER_HOOK_ADDR = 0x4FA64E;
        m_characterHook = std::make_unique<CharacterHook>(CHARACTER_HOOK_ADDR, m_memoryManager.get(),
                                                          reinterpret_cast<uintptr_t>(m_playerPtrBuffer));

        const uintptr_t TARGET_HOOK_ADDR = 0x72A6C5;
        m_targetHook = std::make_unique<TargetHook>(TARGET_HOOK_ADDR, m_memoryManager.get(),
                                                    reinterpret_cast<uintptr_t>(m_targetPtrBuffer));

        const uintptr_t TELEPORT_HOOK_ADDR = 0x7413F0;
        m_teleportHook = std::make_unique<TeleportStepFlagHook>(
            TELEPORT_HOOK_ADDR, reinterpret_cast<uintptr_t>(m_playerPtrBuffer),
            reinterpret_cast<uintptr_t>(m_teleportFlagBuffer), m_memoryManager.get());

        // ИЗМЕНЕНИЕ: Используем правильные методы install/uninstall из НОВОГО HookManager/InlineHook
        if (!m_characterHook->install() || !m_targetHook->install() || !m_teleportHook->install())
        {
            qCCritical(logAppContext) << "Failed to install one or more hooks.";
            detach();
            return false;
        }

        qCInfo(logAppContext) << "All hooks installed successfully.";

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

    if (m_computerNameHook) m_computerNameHook->uninstall();
    m_computerNameHook.reset();

    // ИЗМЕНЕНИЕ: Используем правильный метод uninstall
    if (m_characterHook) m_characterHook->uninstall();
    if (m_targetHook) m_targetHook->uninstall();
    if (m_teleportHook) m_teleportHook->uninstall();

    m_characterHook.reset();
    m_targetHook.reset();
    m_teleportHook.reset();

    if (m_memoryManager && m_memoryManager->isProcessOpen())
    {
        if (m_playerPtrBuffer) m_memoryManager->freeMemory(m_playerPtrBuffer);
        if (m_targetPtrBuffer) m_memoryManager->freeMemory(m_targetPtrBuffer);
        if (m_teleportFlagBuffer) m_memoryManager->freeMemory(m_teleportFlagBuffer);
    }

    m_teleportExecutor.reset();
    m_hookManager.reset();
    m_memoryManager.reset();

    m_pid = 0;
    m_playerPtrBuffer = nullptr;
    m_targetPtrBuffer = nullptr;
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
        return Player(*m_memoryManager.get(), playerAddr);
    }

    return std::nullopt;
}

uintptr_t AppContext::getTeleportFlagBufferAddress() const
{
    return reinterpret_cast<uintptr_t>(m_teleportFlagBuffer);
}

GameObject* AppContext::getTargetObject()
{
    if (!m_memoryManager || !m_targetPtrBuffer)
    {
        return nullptr;
    }

    uintptr_t targetAddr = 0;
    if (m_memoryManager->readMemory(reinterpret_cast<uintptr_t>(m_targetPtrBuffer), targetAddr) && targetAddr != 0)
    {
        return reinterpret_cast<GameObject*>(targetAddr);
    }

    return nullptr;
}