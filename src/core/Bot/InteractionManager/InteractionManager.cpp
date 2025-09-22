#include "InteractionManager.h"
#include "Shared/Data/SharedData.h"  // Нужен для доступа к ClientCommand
#include <QLoggingCategory>

// Создаем свою категорию логов для нового менеджера
Q_LOGGING_CATEGORY(logInteractionManager, "mdbot.interactionmanager")

InteractionManager::InteractionManager(SharedMemoryManager* sharedMemory, QObject* parent)
    : QObject(parent), m_sharedMemory(sharedMemory)
{
    if (!m_sharedMemory)
    {
        qFatal("InteractionManager created with a null SharedMemoryManager!");
    }
    qCInfo(logInteractionManager) << "InteractionManager created.";
}

bool InteractionManager::interactWithTarget(uint64_t targetGuid)
{
    if (!m_sharedMemory) return false;

    SharedData* data = m_sharedMemory->getMemoryPtr();
    if (!data)
    {
        qCCritical(logInteractionManager) << "Cannot interact: Failed to get pointer to shared memory.";
        return false;
    }

    // Проверяем, свободна ли DLL, как и в других менеджерах
    if (data->commandToDll.status != CommandStatus::None)
    {
        qCWarning(logInteractionManager) << "Cannot interact: DLL is busy with another command.";
        return false;
    }

    // Заполняем "бланк заказа" нашей новой, чистой командой
    data->commandToDll.type = ClientCommandType::NativeInteract;
    data->commandToDll.targetGuid = targetGuid;
    data->commandToDll.status = CommandStatus::Pending;

    qCInfo(logInteractionManager) << "NativeInteract command sent for GUID:" << Qt::hex << targetGuid;

    return true;
}