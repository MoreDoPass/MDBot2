#include "IsInCombatCondition.h"
#include "core/BehaviorTree/BTContext.h"

IsInCombatCondition::IsInCombatCondition(UnitSource source, bool mustBeInCombat)
    : m_source(source), m_mustBeInCombat(mustBeInCombat)
{
}

NodeStatus IsInCombatCondition::tick(BTContext& context)
{
    // Шаг 1: Определяем GUID юнита, которого нужно проверить.
    uint64_t guidToCheck = 0;
    if (m_source == UnitSource::Self)
    {
        guidToCheck = context.character->getGuid();
    }
    else  // m_source == UnitSource::CurrentTarget
    {
        guidToCheck = context.currentTargetGuid;
    }

    if (guidToCheck == 0)
    {
        return NodeStatus::Failure;  // Некого проверять
    }

    // Шаг 2: Используем наш новый метод в GameObjectManager!
    bool isInCombat = context.gameObjectManager->isUnitInCombat(guidToCheck);

    // Шаг 3: Сравниваем фактическое состояние с тем, что нам было нужно.
    // Если (мы в бою И нам нужно быть в бою) -> true
    // Если (мы НЕ в бою И нам НЕ нужно быть в бою) -> true
    if (isInCombat == m_mustBeInCombat)
    {
        return NodeStatus::Success;  // Условие выполнено
    }

    return NodeStatus::Failure;  // Условие не выполнено
}