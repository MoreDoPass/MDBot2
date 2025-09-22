#include "IsCastingCondition.h"
#include "core/BehaviorTree/BTContext.h"

IsCastingCondition::IsCastingCondition(UnitSource source, int spellId, bool mustBeCasting)
    : m_source(source), m_spellId(spellId), m_mustBeCasting(mustBeCasting)
{
}

NodeStatus IsCastingCondition::tick(BTContext& context)
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
        // Если некого проверять, то он точно "не кастует".
        // Возвращаем Success, если нам и нужно было, чтобы он не кастовал.
        return !m_mustBeCasting ? NodeStatus::Success : NodeStatus::Failure;
    }

    // Шаг 2: Используем GameObjectManager для получения информации о касте.
    bool isCasting = false;

    if (m_spellId == 0)
    {
        // Режим "проверки любого каста"
        isCasting = context.gameObjectManager->isUnitCasting(guidToCheck);
    }
    else
    {
        // Режим "проверки конкретного заклинания"
        isCasting = (context.gameObjectManager->getUnitCastingSpellId(guidToCheck) == m_spellId);
    }

    // Шаг 3: Сравниваем фактическое состояние с тем, что нам было нужно.
    // Если (юнит кастует И нам нужно, чтобы он кастовал) -> Success
    // Если (юнит НЕ кастует И нам нужно, чтобы он НЕ кастовал) -> Success
    if (isCasting == m_mustBeCasting)
    {
        return NodeStatus::Success;
    }

    return NodeStatus::Failure;
}