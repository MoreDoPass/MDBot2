#include "MovementManager.h"
#include <QLoggingCategory>
#include "core/Bot/Character/Character.h"

Q_LOGGING_CATEGORY(logMovementManager, "mdbot.movementmanager")

/**
 * @brief Конструктор. Теперь принимает SharedMemoryManager.
 */
MovementManager::MovementManager(SharedMemoryManager* sharedMemory, Character* character, QObject* parent)
    : QObject(parent), m_sharedMemory(sharedMemory), m_character(character)
{
    if (!m_sharedMemory)
    {
        qFatal("MovementManager created with a null SharedMemoryManager!");
    }
    qCInfo(logMovementManager) << "MovementManager created.";

    connect(&m_pathExecutorTimer, &QTimer::timeout, this, &MovementManager::updatePathExecution);
}

MovementManager::~MovementManager()
{
    qCInfo(logMovementManager) << "MovementManager destroyed.";
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
    if (data->commandToDll.type != ClientCommandType::None)
    {
        qCWarning(logMovementManager) << "Cannot move: DLL is busy with another command.";
        return false;
    }

    // Формируем и отправляем команду
    data->commandToDll.type = ClientCommandType::MoveTo;
    data->commandToDll.position = position;

    qCInfo(logMovementManager) << "MoveTo command sent to DLL for position (" << position.x << "," << position.y << ","
                               << position.z << ")";

    return true;
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

void MovementManager::setSettings(const MovementSettings& settings)
{
    m_settings = settings;
    qCInfo(logMovementManager) << "Movement settings updated.";
}

MovementSettings MovementManager::settings() const
{
    return m_settings;
}