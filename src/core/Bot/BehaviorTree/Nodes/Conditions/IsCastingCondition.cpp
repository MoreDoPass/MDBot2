#include "IsCastingCondition.h"
#include "core/BehaviorTree/BTContext.h"

IsCastingCondition::IsCastingCondition(UnitSource source, int spellId, bool mustBeCasting)
    : m_source(source), m_spellId(spellId), m_mustBeCasting(mustBeCasting)
{
}

NodeStatus IsCastingCondition::tick(BTContext& context)
{
    bool isCasting = false;
    uint32_t castingSpellId = 0;

    // === НОВАЯ, ПРАВИЛЬНАЯ ЛОГИКА ===
    if (m_source == UnitSource::Self)
    {
        // Если проверяем СЕБЯ, то используем Character!
        // (Нужно будет добавить геттеры isCasting() и getCastingSpellId() в Character)
        isCasting = context.character->isCasting();
        castingSpellId = context.character->getCastingSpellId();
    }
    else  // m_source == UnitSource::CurrentTarget
    {
        // А если проверяем ЦЕЛЬ, то идем в GameObjectManager.
        uint64_t targetGuid = context.currentTargetGuid;
        if (targetGuid != 0)
        {
            isCasting = context.gameObjectManager->isUnitCasting(targetGuid);
            castingSpellId = context.gameObjectManager->getUnitCastingSpellId(targetGuid);
        }
    }

    // Проверяем сам факт каста
    bool finalIsCasting = false;
    if (m_spellId == 0)  // Если проверяем любой каст
    {
        finalIsCasting = isCasting;
    }
    else  // Если проверяем конкретный спелл
    {
        finalIsCasting = (isCasting && castingSpellId == m_spellId);
    }

    // Сравниваем результат с тем, что требовалось
    if (finalIsCasting == m_mustBeCasting)
    {
        return NodeStatus::Success;
    }

    return NodeStatus::Failure;
}