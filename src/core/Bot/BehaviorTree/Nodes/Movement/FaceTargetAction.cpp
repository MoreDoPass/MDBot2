#include "FaceTargetAction.h"
#include "core/BehaviorTree/BTContext.h"
#include <QLoggingCategory>

FaceTargetAction::FaceTargetAction() {}

NodeStatus FaceTargetAction::tick(BTContext& context)
{
    // Проверяем, есть ли у нас вообще цель
    if (context.currentTargetGuid == 0)
    {
        qCWarning(logBT) << "FaceTargetAction failed: currentTargetGuid is 0.";
        return NodeStatus::Failure;
    }

    // Просто вызываем наш новый метод в MovementManager
    bool commandSent = context.movementManager->faceTarget(context.currentTargetGuid);

    if (commandSent)
    {
        // Для реализации через CtM мы предполагаем, что поворот - это быстрое действие.
        // Мы отправляем команду и сразу считаем, что действие успешно инициировано.
        // Чтобы избежать "застревания" дерева, возвращаем Success, а не Running.
        // Игра сама завершит поворот.
        qCDebug(logBT) << "FaceTargetAction SUCCEEDED: Command sent to turn towards GUID" << Qt::hex
                       << context.currentTargetGuid;
        return NodeStatus::Success;
    }

    // Если отправить команду не удалось (например, DLL занята другой командой),
    // действие в этом тике считается проваленным.
    qCWarning(logBT) << "FaceTargetAction FAILED: MovementManager could not send the command.";
    return NodeStatus::Failure;
}