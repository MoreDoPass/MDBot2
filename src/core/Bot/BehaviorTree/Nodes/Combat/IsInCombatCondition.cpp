#include "IsInCombatCondition.h"
#include "core/BehaviorTree/BTContext.h"

IsInCombatCondition::IsInCombatCondition(UnitSource source, bool mustBeInCombat)
    : m_source(source), m_mustBeInCombat(mustBeInCombat)
{
}

NodeStatus IsInCombatCondition::tick(BTContext& context)
{
    bool isInCombat = false;  // Начальное состояние - не в бою

    // === НОВАЯ, ПРАВИЛЬНАЯ ЛОГИКА ===
    if (m_source == UnitSource::Self)
    {
        // Если проверяем СЕБЯ, то используем наш новый "живой" геттер из Character!
        isInCombat = context.character->isInCombat();
    }
    else  // m_source == UnitSource::CurrentTarget
    {
        // А если проверяем ЦЕЛЬ, то идем в GameObjectManager.
        uint64_t targetGuid = context.currentTargetGuid;
        if (targetGuid != 0)
        {
            isInCombat = context.gameObjectManager->isUnitInCombat(targetGuid);
        }
    }

    // Логика сравнения остается той же
    if (isInCombat == m_mustBeInCombat)
    {
        return NodeStatus::Success;
    }

    return NodeStatus::Failure;
}