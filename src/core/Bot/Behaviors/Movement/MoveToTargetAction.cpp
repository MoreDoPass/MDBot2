#include "MoveToTargetAction.h"
#include "core/BehaviorTree/BTNode.h"
#include "Shared/Data/SharedData.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logMoveToAction, "mdbot.bt.action.moveto")

NodeStatus MoveToTargetAction::tick(BTContext& context)
{
    auto gom = context.gameObjectManager;
    auto movementManager = context.movementManager;
    auto character = context.character;

    if (!gom || !movementManager || !character)
    {
        qCCritical(logMoveToAction) << "A required manager is null in BTContext!";
        return NodeStatus::Failure;
    }

    Vector3 targetPosition;
    bool hasTarget = false;

    // --- Сначала ищем цель по GUID ---
    if (context.currentTargetGuid != 0)
    {
        const GameObjectInfo* targetObject = gom->getObjectByGuid(context.currentTargetGuid);
        if (targetObject)
        {
            targetPosition = targetObject->position;
            hasTarget = true;
            qCDebug(logMoveToAction) << "Target found by GUID:" << Qt::hex << context.currentTargetGuid;
        }
        else
        {
            qCWarning(logMoveToAction) << "Target with GUID" << Qt::hex << context.currentTargetGuid
                                       << "is no longer visible. Failing.";
            context.currentTargetGuid = 0;
            return NodeStatus::Failure;
        }
    }
    // --- ИЗМЕНЕНИЕ 1: Проверяем, что вектор не нулевой, по-другому ---
    else if (context.currentTargetPosition.x != 0 || context.currentTargetPosition.y != 0 ||
             context.currentTargetPosition.z != 0)
    {
        targetPosition = context.currentTargetPosition;
        hasTarget = true;
        // --- ИЗМЕНЕНИЕ 2: Используем строчные буквы x, y, z ---
        qCDebug(logMoveToAction) << "Target is a position:" << targetPosition.x << targetPosition.y << targetPosition.z;
    }

    if (!hasTarget)
    {
        qCWarning(logMoveToAction) << "MoveTo failed: no target GUID or position set in context.";
        return NodeStatus::Failure;
    }

    if (character->GetPosition().DistanceSq(targetPosition) < 25.0f)
    {
        qCInfo(logMoveToAction) << "Already at target position. Success.";
        context.currentTargetPosition = Vector3();
        movementManager->stop();
        return NodeStatus::Success;
    }

    SharedData* data = context.movementManager->getSharedMemory()->getMemoryPtr();  // Получаем доступ к памяти
    if (data)
    {
        // Если команда на движение к ЭТОЙ ЖЕ точке уже отправлена,
        // то ничего не делаем, просто продолжаем ждать.
        if (data->commandToDll.type == ClientCommandType::MoveTo &&
            data->commandToDll.position.DistanceSq(targetPosition) < 1.0f)
        {
            qCDebug(logMoveToAction) << "MoveTo command is already active. Waiting...";
            return NodeStatus::Running;
        }
    }

    movementManager->moveTo(targetPosition);
    qCDebug(logMoveToAction) << "MoveTo command sent for position" << targetPosition.x << targetPosition.y
                             << targetPosition.z;

    return NodeStatus::Running;
}