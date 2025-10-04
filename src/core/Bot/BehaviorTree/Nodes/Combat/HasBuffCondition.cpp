#include "HasBuffCondition.h"
#include "core/BehaviorTree/BTContext.h"  // Нужен для доступа к менеджерам

HasBuffCondition::HasBuffCondition(UnitSource target, int auraId, bool mustBePresent)
    : m_target(target), m_auraId(auraId), m_mustBePresent(mustBePresent)
{
    // Конструктор теперь просто инициализирует поля
}

NodeStatus HasBuffCondition::tick(BTContext& context)
{
    bool auraIsPresent = false;  // Начальное состояние - ауры нет

    // === НОВАЯ, ПРАВИЛЬНАЯ ЛОГИКА ===
    if (m_target == UnitSource::Self)
    {
        // Если проверяем СЕБЯ, то используем наш новый "живой" геттер из Character!
        auraIsPresent = context.character->hasAura(m_auraId);
    }
    else  // m_target == UnitSource::CurrentTarget
    {
        // А если проверяем ЦЕЛЬ, то идем в GameObjectManager, как и раньше.
        uint64_t targetGuid = context.currentTargetGuid;
        if (targetGuid != 0)
        {
            auraIsPresent = context.gameObjectManager->unitHasAura(targetGuid, m_auraId);
        }
    }

    // Логика сравнения остается той же самой
    if (auraIsPresent == m_mustBePresent)
    {
        return NodeStatus::Success;
    }

    return NodeStatus::Failure;
}