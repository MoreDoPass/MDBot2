#include "TeleportToTargetAction.h"
#include "core/BehaviorTree/BTNode.h"
#include "Shared/Data/SharedData.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logTeleportToAction, "mdbot.bt.action.teleportto")

NodeStatus TeleportToTargetAction::tick(BTContext& context)
{
    auto gom = context.gameObjectManager;
    auto movementManager = context.movementManager;
    auto character = context.character;

    if (!gom || !movementManager || !character)
    {
        qCCritical(logTeleportToAction) << "A required manager is null in BTContext!";
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
            qCDebug(logTeleportToAction) << "Target found by GUID:" << Qt::hex << context.currentTargetGuid;
        }
        else
        {
            qCWarning(logTeleportToAction)
                << "Target with GUID" << Qt::hex << context.currentTargetGuid << "is no longer visible. Failing.";
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
        qCDebug(logTeleportToAction) << "Target is a position:" << targetPosition.x << targetPosition.y
                                     << targetPosition.z;
    }

    if (!hasTarget)
    {
        qCWarning(logTeleportToAction) << "Teleport failed: no target GUID or position set in context.";
        return NodeStatus::Failure;
    }

    if (character->GetPosition().DistanceSq(targetPosition) < 4.0f)
    {
        qCInfo(logTeleportToAction) << "Already at target position. Success.";
        context.currentTargetPosition = Vector3();
        return NodeStatus::Success;
    }

    qCInfo(logTeleportToAction) << "TeleportTo command sent for position" << targetPosition.x << targetPosition.y
                                << targetPosition.z;
    bool teleportInitiated = movementManager->teleportTo(targetPosition);

    return teleportInitiated ? NodeStatus::Success : NodeStatus::Failure;
}