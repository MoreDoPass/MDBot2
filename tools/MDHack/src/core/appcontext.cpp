#include "appcontext.h"
#include <QLoggingCategory>

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
bool AppContext::attachToProcess(uint32_t pid, const std::wstring& processName)
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
        // СОЗДАЕМ GameObjectManager
        m_gameObjectManager = std::make_unique<GameObjectManager>(m_memoryManager.get());
        m_pid = pid;
        qCInfo(logAppContext) << "Successfully attached to process" << pid;

        // 2. Создаем HookManager, передав ему наш MemoryManager
        m_hookManager = std::make_unique<HookManager>(m_memoryManager.get());

        // 3. Выделяем память в целевом процессе для наших нужд
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

        // 4. Создаем хуки, используя компоненты из MDBot2

        // Адрес для CharacterHook, универсальный для 3.3.5a
        const uintptr_t CHARACTER_HOOK_ADDR = 0x4FA64E;
        auto characterHook = std::make_unique<CharacterHook>(CHARACTER_HOOK_ADDR, m_memoryManager.get(),
                                                             reinterpret_cast<uintptr_t>(m_playerPtrBuffer));

        // Адрес для TeleportStepFlagHook
        const uintptr_t TELEPORT_HOOK_ADDR = 0x7413F0;
        auto teleportHook = std::make_unique<TeleportStepFlagHook>(
            TELEPORT_HOOK_ADDR, reinterpret_cast<uintptr_t>(m_playerPtrBuffer),
            reinterpret_cast<uintptr_t>(m_teleportFlagBuffer), m_memoryManager.get());

        // 5. Добавляем хуки в менеджер и устанавливаем их.
        // HookManager из MDBot2 пока не поддерживает unique_ptr, поэтому используем .get()
        // В будущем можно будет улучшить HookManager для передачи владения.
        m_hookManager->addHook(characterHook->address(), nullptr);
        m_hookManager->addHook(teleportHook->address(), nullptr);

        // ВАЖНО: нужно будет реализовать установку хуков в HookManager. Пока предположим, что она есть.
        // m_hookManager->installAll();
        characterHook->install();  // Пока устанавливаем вручную
        teleportHook->install();   // Пока устанавливаем вручную

        // Запоминаем хуки, чтобы они не удалились после выхода из функции
        // (Это временное решение, пока HookManager не управляет временем жизни)
        // В идеале HookManager должен принимать std::unique_ptr
        characterHook.release();
        teleportHook.release();

        // 6. Создаем исполнителя телепортации
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

    // Менеджер хуков должен сам снимать все хуки в своем деструкторе,
    // но мы можем это сделать и явно для надежности.
    if (m_hookManager)
    {
        // m_hookManager->uninstallAll(); // Когда будет реализовано
    }

    // Освобождаем память, выделенную в целевом процессе
    if (m_memoryManager && m_memoryManager->isProcessOpen())
    {
        if (m_playerPtrBuffer) m_memoryManager->freeMemory(m_playerPtrBuffer);
        if (m_teleportFlagBuffer) m_memoryManager->freeMemory(m_teleportFlagBuffer);
    }

    // Порядок удаления важен: сначала объекты, использующие менеджеры,
    // потом сами менеджеры. unique_ptr сделает это за нас.
    m_teleportExecutor.reset();
    m_hookManager.reset();
    m_memoryManager.reset();  // Закроет хендл процесса в своем деструкторе

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