#include "HasTargetCondition.h"
#include "core/BehaviorTree/BTContext.h"  // Нужен для доступа к контексту
#include <QLoggingCategory>

// Используем общую категорию для узлов Дерева Поведения
Q_DECLARE_LOGGING_CATEGORY(logBT)

HasTargetCondition::HasTargetCondition() {}

NodeStatus HasTargetCondition::tick(BTContext& context)
{
    if (context.currentTargetGuid != 0)
    {
        qCDebug(logBT) << "HasTargetCondition SUCCEEDED: Target exists with GUID" << Qt::hex
                       << context.currentTargetGuid;
        // Цель есть, условие выполнено.
        return NodeStatus::Success;
    }

    qCDebug(logBT) << "HasTargetCondition FAILED: No target.";
    // Цели нет, условие провалено.
    return NodeStatus::Failure;
}