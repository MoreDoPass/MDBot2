#include "MoveToTargetAction.h"
#include "core/BehaviorTree/BTNode.h"
#include "Shared/Data/SharedData.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logMoveToAction, "mdbot.bt.action.moveto")

NodeStatus MoveToTargetAction::tick(BTContext& context)
{
    if (context.currentTargetGuid == 0)
    {
        qCWarning(logMoveToAction) << "MoveToTargetAction failed: currentTargetGuid is 0.";
        return NodeStatus::Failure;
    }

    auto gom = context.gameObjectManager;
    auto movementManager = context.movementManager;
    if (!gom || !movementManager)
    {
        qCCritical(logMoveToAction) << "Manager is null in BTContext!";
        return NodeStatus::Failure;
    }

    // Теперь getObjectByGuid возвращает const GameObjectInfo*
    const GameObjectInfo* targetObject = gom->getObjectByGuid(context.currentTargetGuid);
    if (!targetObject)
    {
        qCWarning(logMoveToAction) << "MoveToTargetAction failed: Can't find object with GUID:" << Qt::hex
                                   << context.currentTargetGuid;
        // Сбрасываем GUID, т.к. цель больше не валидна
        context.currentTargetGuid = 0;
        return NodeStatus::Failure;
    }

    // --- ГЛАВНОЕ УПРОЩЕНИЕ ---
    // У GameObjectInfo поле position есть всегда. Больше не нужны switch и касты.
    const Vector3& targetPosition = targetObject->position;

    // --- Дальнейшая логика остается без изменений ---

    // Проверяем, не находимся ли мы уже достаточно близко к цели (5*5=25)
    if (context.character->GetPosition().DistanceSq(targetPosition) < 25.0f)
    {
        qCInfo(logMoveToAction) << "Already at target. Success.";
        return NodeStatus::Success;
    }

    // Отправляем команду на движение
    movementManager->moveTo(targetPosition);
    qCInfo(logMoveToAction) << "MoveTo command sent for target" << Qt::hex << context.currentTargetGuid;

    // Возвращаем Running, т.к. движение - это длительный процесс.
    // Дерево будет проверять статус на следующих тиках.
    return NodeStatus::Running;
}