#include "IsAutoAttackingCondition.h"
#include "core/BehaviorTree/BTContext.h"

IsAutoAttackingCondition::IsAutoAttackingCondition(UnitSource source, bool mustBeAttacking)
    : m_source(source), m_mustBeAttacking(mustBeAttacking)
{
    // Конструктор просто сохраняет инструкции
}

NodeStatus IsAutoAttackingCondition::tick(BTContext& context)
{
    bool isAttacking = false;  // Начальное предположение - не атакует

    if (m_source == UnitSource::Self)
    {
        // Если проверяем себя, обращаемся к Character
        isAttacking = context.character->isAutoAttacking();
    }
    else  // m_source == UnitSource::CurrentTarget
    {
        // Если проверяем цель, обращаемся к GameObjectManager
        uint64_t targetGuid = context.currentTargetGuid;
        if (targetGuid != 0)
        {
            isAttacking = context.gameObjectManager->isAutoAttacking(targetGuid);
        }
    }

    // Сравниваем реальное состояние с тем, которое нам нужно
    if (isAttacking == m_mustBeAttacking)
    {
        // Состояние совпало с ожиданием - успех
        return NodeStatus::Success;
    }

    // Состояние не совпало - провал
    return NodeStatus::Failure;
}