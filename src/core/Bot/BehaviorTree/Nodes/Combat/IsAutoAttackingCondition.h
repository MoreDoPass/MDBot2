#pragma once

#include "core/BehaviorTree/ConditionNode.h"
#include "core/Bot/BehaviorTree/Nodes/Shared/UnitSource.h"

/**
 * @class IsAutoAttackingCondition
 * @brief Узел-условие для проверки, активна ли автоатака у указанного юнита
 *        (нашего персонажа или текущей цели).
 */
class IsAutoAttackingCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param source Кто является целью проверки (мы или наша цель).
     * @param mustBeAttacking Если true, узел вернет Success, если юнит АТАКУЕТ.
     *                        Если false, узел вернет Success, если юнит НЕ атакует.
     */
    IsAutoAttackingCondition(UnitSource source, bool mustBeAttacking = true);

    NodeStatus tick(BTContext& context) override;

   private:
    UnitSource m_source;
    bool m_mustBeAttacking;
};