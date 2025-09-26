#include "MovementManager.h"
#include "core/Bot/Character/Character.h"
#include "core/MemoryManager/MemoryManager.h"
#include "core/Bot/GameObjectManager/GameObjectManager.h"
#include "core/Bot/Movement/Teleport/TeleportExecutor.h"
#include "core/Bot/Movement/Teleport/TeleportStepFlagHook.h"
#include <QLoggingCategory>
#include <optional>  // Для работы с std::optional
#include <cmath>

Q_LOGGING_CATEGORY(logMovementManager, "mdbot.movementmanager")

// Адреса и смещения для системы телепортации.
// В идеале их нужно вынести в файл с настройками/офсетами.
namespace TeleportOffsets
{
constexpr uintptr_t HookAddress = 0x7413F0;
}  // namespace TeleportOffsets

/**
 * @brief Конструктор. Теперь принимает SharedMemoryManager.
 */
MovementManager::MovementManager(SharedMemoryManager* sharedMemory, MemoryManager* memoryManager, Character* character,
                                 GameObjectManager* gom, QObject* parent)
    : QObject(parent),
      m_sharedMemory(sharedMemory),
      m_memoryManager(memoryManager),
      m_character(character),
      m_gameObjectManager(gom)  // <-- Сохраняем указатель в наше новое поле
{
    if (!m_sharedMemory || !m_memoryManager || !m_character)
    {
        qFatal("MovementManager created with a null dependency!");
    }
    qCInfo(logMovementManager) << "MovementManager created.";

    // Создаем исполнителя телепортации
    m_teleportExecutor = std::make_unique<TeleportExecutor>(m_memoryManager);

    // Инициализируем подсистему телепортации
    if (!initializeTeleportSystem())
    {
        qCCritical(logMovementManager) << "Teleport system initialization failed! Teleportation will be unavailable.";
    }

    connect(&m_pathExecutorTimer, &QTimer::timeout, this, &MovementManager::updatePathExecution);
}

MovementManager::~MovementManager()
{
    // Корректно очищаем ресурсы, выделенные для телепортации
    shutdownTeleportSystem();
    qCInfo(logMovementManager) << "MovementManager destroyed.";
}

bool MovementManager::initializeTeleportSystem()
{
    if (m_teleportSystemInitialized || !m_memoryManager->isProcessOpen())
    {
        qCWarning(logMovementManager) << "Cannot initialize teleport system: already initialized or process not open.";
        return false;
    }

    // 1. Выделяем память. Теперь Player Buffer просто пустой.
    void* allocatedPlayerBuffer = m_memoryManager->allocMemory(sizeof(uintptr_t));
    void* allocatedFlagBuffer = m_memoryManager->allocMemory(sizeof(uint8_t));

    m_playerStructAddrBuffer = reinterpret_cast<uintptr_t>(allocatedPlayerBuffer);
    m_flagBuffer = reinterpret_cast<uintptr_t>(allocatedFlagBuffer);

    if (!m_playerStructAddrBuffer || !m_flagBuffer)
    {
        qCCritical(logMovementManager) << "Failed to allocate memory for teleport system in target process.";
        shutdownTeleportSystem();
        return false;
    }
    qCInfo(logMovementManager) << "Allocated memory for teleport: player buffer at" << Qt::hex
                               << m_playerStructAddrBuffer << ", flag buffer at" << m_flagBuffer;

    // 2. Создаем и устанавливаем хук. Запись адреса теперь будет в teleportTo.
    m_teleportHook = std::make_unique<TeleportStepFlagHook>(TeleportOffsets::HookAddress, m_playerStructAddrBuffer,
                                                            m_flagBuffer, m_memoryManager);
    if (!m_teleportHook->install())
    {
        qCCritical(logMovementManager) << "Failed to install TeleportStepFlagHook.";
        shutdownTeleportSystem();
        return false;
    }

    qCInfo(logMovementManager) << "Teleport system initialized successfully.";
    m_teleportSystemInitialized = true;
    return true;
}

void MovementManager::shutdownTeleportSystem()
{
    // Сначала удаляем хук (деструктор unique_ptr вызовет деструктор хука, который его снимет)
    m_teleportHook.reset();

    // Затем освобождаем память, которую мы выделили в процессе игры
    if (m_memoryManager && m_memoryManager->isProcessOpen())
    {
        // ИСПРАВЛЕНО: Используем правильный метод `freeMemory` с правильными аргументами
        if (m_playerStructAddrBuffer)
        {
            m_memoryManager->freeMemory(reinterpret_cast<void*>(m_playerStructAddrBuffer));
        }
        if (m_flagBuffer)
        {
            m_memoryManager->freeMemory(reinterpret_cast<void*>(m_flagBuffer));
        }
    }

    m_playerStructAddrBuffer = 0;
    m_flagBuffer = 0;
    m_teleportSystemInitialized = false;
    qCInfo(logMovementManager) << "Teleport system shut down.";
}

/**
 * @brief Отправляет команду на движение в DLL через общую память.
 */
bool MovementManager::moveTo(const Vector3& position)
{
    if (!m_sharedMemory)
    {
        qCCritical(logMovementManager) << "Cannot move: SharedMemoryManager is not available.";
        return false;
    }

    SharedData* data = m_sharedMemory->getMemoryPtr();
    if (!data)
    {
        qCCritical(logMovementManager) << "Cannot move: Failed to get pointer to shared memory.";
        return false;
    }

    // Проверяем, не занята ли DLL выполнением другой команды.
    // В будущем можно будет сделать очередь команд.
    if (data->commandToDll.status != CommandStatus::None)
    {
        qCWarning(logMovementManager) << "Cannot move: DLL is busy with another command.";
        return false;
    }

    // Формируем и отправляем команду
    data->commandToDll.type = ClientCommandType::MoveTo;
    data->commandToDll.position = position;
    data->commandToDll.status = CommandStatus::Pending;

    qCInfo(logMovementManager) << "MoveTo command sent to DLL for position (" << position.x << "," << position.y << ","
                               << position.z << ")";

    return true;
}

bool MovementManager::teleportTo(const Vector3& position)
{
    if (!m_teleportSystemInitialized)
    {
        qCWarning(logMovementManager) << "Cannot teleport: system is not initialized.";
        return false;
    }

    const uintptr_t playerBase = m_character->getBaseAddress();
    const std::optional<DWORD> optionalPid = m_memoryManager->pid();

    if (playerBase == 0 || !optionalPid.has_value())
    {
        qCWarning(logMovementManager) << "Cannot teleport: invalid player address or PID. Player is not in world?";
        return false;
    }
    const DWORD pid = optionalPid.value();

    // --- КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ ---
    // Перед началом телепортации записываем актуальный адрес игрока
    // в наш буфер, чтобы хук знал, с чем сравнивать.
    if (!m_memoryManager->writeMemory(m_playerStructAddrBuffer, playerBase))
    {
        qCCritical(logMovementManager)
            << "Failed to write current player base address to remote buffer. Aborting teleport.";
        return false;
    }

    qCInfo(logMovementManager) << "Teleporting to (" << position.x << "," << position.y << "," << position.z << ")";

    return m_teleportExecutor->setPositionStepwise(playerBase, pid, m_flagBuffer, position.x, position.y, position.z);
}

void MovementManager::stop()
{
    qCInfo(logMovementManager) << "Stop command sent to DLL.";
    m_pathExecutorTimer.stop();
    m_currentPath.clear();
    m_currentPathIndex = -1;

    if (!m_sharedMemory) return;
    SharedData* data = m_sharedMemory->getMemoryPtr();
    if (!data) return;

    // Отправляем команду Stop
    data->commandToDll.type = ClientCommandType::Stop;
}

// Методы onPathFound и updatePathExecution пока остаются без изменений,
// так как они отвечают за логику следования по пути, а не за сам CtM.
// Мы их адаптируем, когда будем реализовывать полноценное движение по путевым точкам.
// Сейчас для теста нам достаточно простого moveTo.

void MovementManager::onPathFound(std::vector<Vector3> path)
{
    // TODO: Адаптировать для новой системы
}

void MovementManager::updatePathExecution()
{
    // TODO: Адаптировать для новой системы
}

bool MovementManager::faceTarget(uint64_t targetGuid)
{
    // 1. Проверяем, можем ли мы вообще отправить команду
    if (!m_sharedMemory) return false;
    SharedData* data = m_sharedMemory->getMemoryPtr();
    if (!data || data->commandToDll.status != CommandStatus::None)
    {
        qCWarning(logMovementManager) << "Cannot face target: DLL is busy or SharedMemory is unavailable.";
        return false;
    }

    // 2. Получаем "живые" данные о позициях
    const Vector3 selfPos = m_character->getPosition();
    const GameObjectInfo* targetInfo = m_gameObjectManager->getObjectByGuid(targetGuid);

    if (!targetInfo)
    {
        qCWarning(logMovementManager) << "Cannot face target: Target GUID" << targetGuid << "not found.";
        return false;
    }
    const Vector3 targetPos = targetInfo->position;

    // 3. === ГЛАВНАЯ МАТЕМАТИКА ===
    // Вычисляем угол между двумя точками на плоскости XY.
    // atan2 - стандартная функция, которая делает именно это. Она возвращает угол в радианах.
    float angleToTarget = atan2(targetPos.y - selfPos.y, targetPos.x - selfPos.x);

    // 4. Формируем и отправляем НОВУЮ команду
    data->commandToDll.type = ClientCommandType::SetOrientation;
    data->commandToDll.orientation = angleToTarget;  // <-- Кладем вычисленный угол в новое поле
    data->commandToDll.status = CommandStatus::Pending;

    qCInfo(logMovementManager) << "SetOrientation command sent to DLL for target" << targetGuid
                               << "with angle:" << angleToTarget;

    return true;
}