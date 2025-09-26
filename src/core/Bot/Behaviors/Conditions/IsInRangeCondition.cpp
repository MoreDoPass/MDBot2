#include "IsInRangeCondition.h"
#include "core/BehaviorTree/BTContext.h"  // Нужен для доступа к данным
#include <QLoggingCategory>

// Используем общую категорию для узлов Дерева Поведения
Q_DECLARE_LOGGING_CATEGORY(logBT)

IsInRangeCondition::IsInRangeCondition(float distance)
    // Сразу вычисляем и сохраняем квадрат дистанции.
    // Это оптимизация, чтобы не делать умножение на каждом тике.
    : m_distanceSq(distance * distance)
{
}

NodeStatus IsInRangeCondition::tick(BTContext& context)
{
    if (context.currentTargetGuid == 0)
    {
        return NodeStatus::Failure;
    }

    // === НОВАЯ, ПРАВИЛЬНАЯ ЛОГИКА ===
    // 1. Получаем позицию нашего персонажа НАПРЯМУЮ из Character.
    const Vector3 selfPosition = context.character->getPosition();

    // 2. Получаем информацию о цели из GameObjectManager, как и раньше.
    const GameObjectInfo* targetInfo = context.gameObjectManager->getObjectByGuid(context.currentTargetGuid);

    if (!targetInfo)
    {
        // Цель могла исчезнуть, это нормально.
        return NodeStatus::Failure;
    }

    // 3. Считаем дистанцию между нашей позицией и позицией цели.
    if (selfPosition.DistanceSq(targetInfo->position) <= m_distanceSq)
    {
        return NodeStatus::Success;
    }

    return NodeStatus::Failure;
}