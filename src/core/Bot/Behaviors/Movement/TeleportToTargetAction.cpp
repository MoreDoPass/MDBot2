#include "TeleportToTargetAction.h"
#include "core/BehaviorTree/BTContext.h"
#include "Shared/Data/SharedData.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logTeleportToAction, "mdbot.bt.action.teleportto")

TeleportToTargetAction::TeleportToTargetAction(float offsetDistance) : m_offsetDistance(offsetDistance) {}

NodeStatus TeleportToTargetAction::tick(BTContext& context)
{
    // --- ШАГ 1: Получаем все необходимые менеджеры (без изменений) ---
    auto gom = context.gameObjectManager;
    auto movementManager = context.movementManager;
    auto character = context.character;

    if (!gom || !movementManager || !character)
    {
        qCCritical(logTeleportToAction) << "A required manager is null in BTContext!";
        return NodeStatus::Failure;
    }

    // --- ШАГ 2: УНИВЕРСАЛЬНОЕ ОПРЕДЕЛЕНИЕ ЦЕЛИ (ВОТ ГЛАВНОЕ ИСПРАВЛЕНИЕ) ---
    Vector3 targetPosition;
    bool hasTarget = false;

    // Сначала пытаемся найти цель по GUID (приоритет для боя)
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
            // Цель с таким GUID больше не видна - это провал.
            qCWarning(logTeleportToAction)
                << "Target with GUID" << Qt::hex << context.currentTargetGuid << "is no longer visible. Failing.";
            context.currentTargetGuid = 0;  // Сбрасываем неактуальный GUID
            return NodeStatus::Failure;
        }
    }
    // Если GUID нет, ищем цель по координатам (для маршрутов, руды и т.д.)
    else if (!context.currentTargetPosition.isZero())  // Используем метод isZero() или аналог
    {
        targetPosition = context.currentTargetPosition;
        hasTarget = true;
        qCDebug(logTeleportToAction) << "Target is a raw position:" << targetPosition.x << targetPosition.y
                                     << targetPosition.z;
    }

    // Если после всех проверок цели так и не нашлось
    if (!hasTarget)
    {
        qCWarning(logTeleportToAction) << "Teleport failed: no target GUID or position set in context.";
        return NodeStatus::Failure;
    }

    // --- ШАГ 3: Вычисляем конечную точку с учетом смещения (логика остается) ---
    Vector3 finalDestination = targetPosition;
    const Vector3 selfPosition = character->getPosition();

    if (m_offsetDistance > 0.01f)
    {
        Vector3 direction = targetPosition - selfPosition;
        direction.Normalize();
        finalDestination = targetPosition - (direction * m_offsetDistance);
    }

    // --- ШАГ 4: Проверяем дистанцию и выполняем телепорт (логика остается) ---
    if (selfPosition.DistanceSq(finalDestination) < 4.0f)  // 2*2 ярда
    {
        qCInfo(logTeleportToAction) << "Already at/near destination. Success.";
        // Важно! Сбрасываем позиционную цель, когда дошли до нее.
        context.currentTargetPosition = Vector3();
        return NodeStatus::Success;
    }

    qCInfo(logTeleportToAction) << "TeleportTo command sent for position" << finalDestination.x << finalDestination.y
                                << finalDestination.z;
    bool teleportInitiated = movementManager->teleportTo(finalDestination);

    return teleportInitiated ? NodeStatus::Success : NodeStatus::Failure;
}