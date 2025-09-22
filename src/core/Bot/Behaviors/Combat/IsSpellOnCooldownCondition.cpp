// Файл: core/Bot/Behaviors/Combat/IsSpellOnCooldownCondition.cpp
#include "IsSpellOnCooldownCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logBTCondition, "mdbot.bt.condition")

IsSpellOnCooldownCondition::IsSpellOnCooldownCondition(int spellId) : m_spellId(spellId) {}

NodeStatus IsSpellOnCooldownCondition::tick(BTContext& context)
{
    // Проверка №1: Глобальный Кулдаун (ГКД).
    // Это самая частая проверка, поэтому делаем ее первой.
    if (context.character->isGcdActive())
    {
        // Если ГКД активен, дальше можно не проверять.
        qCDebug(logBTCondition) << "IsSpellOnCooldownCondition FAILED for spell" << m_spellId << ": GCD is active.";
        return NodeStatus::Failure;
    }

    // Проверка №2: Личный кулдаун самого заклинания.
    if (context.character->isSpellOnCooldown(m_spellId))
    {
        // Если заклинание на своем КД, оно не готово.
        qCDebug(logBTCondition) << "IsSpellOnCooldownCondition FAILED for spell" << m_spellId
                                << ": Spell is on its own cooldown.";
        return NodeStatus::Failure;
    }

    // Если мы прошли обе проверки, значит, кулдауны заклинания готовы.
    qCDebug(logBTCondition) << "IsSpellOnCooldownCondition SUCCEEDED for spell" << m_spellId;
    return NodeStatus::Success;
}