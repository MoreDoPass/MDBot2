#include "StartAutoAttackAction.h"
#include "core/BehaviorTree/BTContext.h"
#include <QLoggingCategory>

StartAutoAttackAction::StartAutoAttackAction()
{
    // Конструктор пуст
}

NodeStatus StartAutoAttackAction::tick(BTContext& context)
{
    // Шаг 1: Получаем GUID цели из контекста
    const uint64_t targetGuid = context.currentTargetGuid;

    // Если цели нет, мы не можем атаковать. Действие провалено.
    if (targetGuid == 0)
    {
        qCWarning(logBT) << "StartAutoAttackAction failed: currentTargetGuid is 0 in BTContext.";
        return NodeStatus::Failure;
    }

    // Шаг 2: Отдаем приказ "рукам" (CombatManager)
    const bool commandSent = context.combatManager->startAutoAttack(targetGuid);

    if (commandSent)
    {
        // Команда успешно отправлена в DLL.
        // Мы не знаем, сколько времени займет у персонажа подбежать и ударить,
        // но сама команда выполнена мгновенно. С точки зрения дерева,
        // действие успешно инициировано.
        // Возвращаем Success, чтобы дерево могло перейти к следующему узлу (например, касту).
        return NodeStatus::Success;
    }

    // Если отправить команду не удалось (например, CombatManager занят),
    // то в этот тик действие провалено. Дерево попробует снова в следующий раз.
    return NodeStatus::Failure;
}