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
    // Шаг 1: Проверяем, есть ли у нас вообще цель.
    if (context.currentTargetGuid == 0)
    {
        qCDebug(logBT) << "IsInRangeCondition FAILED: No target selected.";
        return NodeStatus::Failure;
    }

    // Шаг 2: Получаем объекты себя и цели из менеджера.
    const GameObjectInfo* selfInfo = context.gameObjectManager->getObjectByGuid(context.character->getGuid());
    const GameObjectInfo* targetInfo = context.gameObjectManager->getObjectByGuid(context.currentTargetGuid);

    // Если один из объектов не найден (например, цель исчезла), проваливаем условие.
    if (!selfInfo || !targetInfo)
    {
        qCDebug(logBT) << "IsInRangeCondition FAILED: Could not find self or target object info.";
        return NodeStatus::Failure;
    }

    // Шаг 3: Вычисляем квадрат расстояния и сравниваем.
    const float currentDistanceSq = selfInfo->position.DistanceSq(targetInfo->position);

    if (currentDistanceSq <= m_distanceSq)
    {
        // Мы в пределах досягаемости.
        qCDebug(logBT) << "IsInRangeCondition SUCCEEDED: DistanceSq" << currentDistanceSq << "<=" << m_distanceSq;
        return NodeStatus::Success;
    }

    // Мы слишком далеко.
    qCDebug(logBT) << "IsInRangeCondition FAILED: DistanceSq" << currentDistanceSq << ">" << m_distanceSq;
    return NodeStatus::Failure;
}