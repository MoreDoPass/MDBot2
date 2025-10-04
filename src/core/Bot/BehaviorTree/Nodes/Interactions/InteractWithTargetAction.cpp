#include "InteractWithTargetAction.h"
#include "core/BehaviorTree/BTContext.h"  // Нужен для доступа к контексту
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logInteractAction, "mdbot.bt.action.interact")

InteractWithTargetAction::InteractWithTargetAction() {}

NodeStatus InteractWithTargetAction::tick(BTContext& context)
{
    const uint64_t targetGuid = context.currentTargetGuid;
    if (targetGuid == 0)
    {
        qCWarning(logInteractAction) << "InteractWithTargetAction FAILED: currentTargetGuid is 0.";
        return NodeStatus::Failure;
    }

    // Вызываем наш новый, простой метод из InteractionManager
    // Убедись, что context.interactionManager уже инициализирован!
    bool commandSent = context.interactionManager->interactWithTarget(targetGuid);

    if (commandSent)
    {
        qCDebug(logInteractAction) << "InteractWithTargetAction SUCCEEDED: Command sent for GUID" << Qt::hex
                                   << targetGuid;
        return NodeStatus::Success;
    }

    qCWarning(logInteractAction) << "InteractWithTargetAction FAILED: Manager could not send the command.";
    return NodeStatus::Failure;
}