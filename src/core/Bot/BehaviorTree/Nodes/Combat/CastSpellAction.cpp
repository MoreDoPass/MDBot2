#include "CastSpellAction.h"
#include "core/BehaviorTree/BTContext.h"

CastSpellAction::CastSpellAction(UnitSource target, int spellId) : m_target(target), m_spellId(spellId)
{
    // Конструктор просто сохраняет наши инструкции
}

NodeStatus CastSpellAction::tick(BTContext& context)
{
    // --- Шаг 1: Определяем GUID цели для заклинания, следуя инструкции 'm_target' ---
    uint64_t targetGuid = 0;
    if (m_target == UnitSource::Self)
    {
        // Инструкция "Self": целью будем мы сами
        targetGuid = context.character->getGuid();
    }
    else  // m_target == UnitSource::CurrentTarget
    {
        // Инструкция "CurrentTarget": целью будет тот, кто сейчас в контексте
        targetGuid = context.currentTargetGuid;
    }

    // Если мы не знаем, в кого кастовать (например, цель не выбрана), действие провалено.
    if (targetGuid == 0)
    {
        return NodeStatus::Failure;
    }

    // --- Шаг 2: Отдаем приказ "рукам" (CombatManager) ---
    // Вызываем тот самый метод, который ты мне показал.
    bool commandSent = context.combatManager->castSpellOnTarget(m_spellId, targetGuid);

    if (commandSent)
    {
        // Команда успешно отправлена в DLL.
        // Действие еще не завершено (заклинание может кастоваться), поэтому возвращаем Running.
        // Это не даст дереву делать что-то еще в этот "тик".
        return NodeStatus::Running;
    }

    // Если отправить команду не удалось (например, CombatManager занят другим приказом),
    // то действие провалено.
    return NodeStatus::Failure;
}