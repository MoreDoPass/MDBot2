#include "HasTargetCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(logBT)

HasTargetCondition::HasTargetCondition(GameObjectType requiredType) : m_requiredType(requiredType) {}

NodeStatus HasTargetCondition::tick(BTContext& context)
{
    // Шаг 1: Простая проверка на наличие GUID'а. Если его нет - провал.
    if (context.currentTargetGuid == 0)
    {
        qCDebug(logBT) << "HasTargetCondition FAILED: No target GUID in context.";
        return NodeStatus::Failure;
    }

    // Шаг 2: Если нам не важен тип (старое поведение), то задача выполнена.
    if (m_requiredType == GameObjectType::None)
    {
        qCDebug(logBT) << "HasTargetCondition SUCCEEDED: Target exists with GUID" << Qt::hex
                       << context.currentTargetGuid;
        return NodeStatus::Success;
    }

    // Шаг 3: Если нам важен тип, проводим полную проверку.
    const GameObjectInfo* targetInfo = context.gameObjectManager->getObjectByGuid(context.currentTargetGuid);
    if (!targetInfo)
    {
        qCDebug(logBT) << "HasTargetCondition FAILED: Target GUID exists, but object is not visible.";
        // GUID есть, но самого объекта уже нет в зоне видимости.
        return NodeStatus::Failure;
    }

    // Сравниваем тип цели с тем, который нам нужен.
    if (targetInfo->type == m_requiredType)
    {
        qCDebug(logBT) << "HasTargetCondition SUCCEEDED: Target" << Qt::hex << context.currentTargetGuid
                       << "has the required type.";
        // Тип совпадает! Это правильная цель.
        return NodeStatus::Success;
    }

    qCDebug(logBT) << "HasTargetCondition FAILED: Target" << Qt::hex << context.currentTargetGuid
                   << "does NOT have the required type.";
    // Это цель, но НЕ того типа (например, Unit вместо GameObject).
    return NodeStatus::Failure;
}