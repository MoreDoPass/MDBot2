#include "ClearTargetAction.h"
#include "core/BehaviorTree/BTContext.h"
#include <QLoggingCategory>

// Используем общую категорию для узлов Дерева Поведения
Q_DECLARE_LOGGING_CATEGORY(logBT)

ClearTargetAction::ClearTargetAction() {}

NodeStatus ClearTargetAction::tick(BTContext& context)
{
    if (context.currentTargetGuid != 0)
    {
        qCDebug(logBT) << "ClearTargetAction: Clearing target with GUID" << Qt::hex << context.currentTargetGuid;
        context.currentTargetGuid = 0;
    }

    // Это действие не может провалиться.
    return NodeStatus::Success;
}