#include "TeleportToTargetAction.h"
#include "core/BehaviorTree/BTNode.h"
#include "Shared/Data/SharedData.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logTeleportToAction, "mdbot.bt.action.teleportto")

NodeStatus TeleportToTargetAction::tick(BTContext& context)
{
    if (context.currentTargetGuid == 0)
    {
        qCWarning(logTeleportToAction) << "TeleportToTargetAction failed: currentTargetGuid is 0.";
        return NodeStatus::Failure;
    }

    auto gom = context.gameObjectManager;
    auto movementManager = context.movementManager;
    if (!gom || !movementManager)
    {
        qCCritical(logTeleportToAction) << "Manager is null in BTContext!";
        return NodeStatus::Failure;
    }

    const GameObjectInfo* targetObject = gom->getObjectByGuid(context.currentTargetGuid);
    if (!targetObject)
    {
        qCWarning(logTeleportToAction) << "TeleportToTargetAction failed: Can't find object with GUID:" << Qt::hex
                                       << context.currentTargetGuid;
        context.currentTargetGuid = 0;  // Сбрасываем GUID, т.к. цель больше не валидна
        return NodeStatus::Failure;
    }

    const Vector3& targetPosition = targetObject->position;

    // Проверяем, не находимся ли мы уже у цели. Используем маленькую дистанцию, т.к. телепорт точный. (2*2=4)
    if (context.character->GetPosition().DistanceSq(targetPosition) < 4.0f)
    {
        qCInfo(logTeleportToAction) << "Already at target. Success.";
        return NodeStatus::Success;
    }

    // Отправляем команду на телепортацию
    qCInfo(logTeleportToAction) << "TeleportTo command sent for target" << Qt::hex << context.currentTargetGuid;
    bool teleportInitiated = movementManager->teleportTo(targetPosition);

    // Телепортация - это быстрая операция. Мы считаем ее либо успешной, либо провальной сразу.
    // Если teleportTo вернет true, значит все прошло хорошо.
    return teleportInitiated ? NodeStatus::Success : NodeStatus::Failure;
}