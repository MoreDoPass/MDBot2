#pragma once

#include "core/BehaviorTree/ConditionNode.h"
#include "core/Bot/BehaviorTree/Nodes/Shared/UnitSource.h"

/**
 * @class IsInCombatCondition
 * @brief Универсальный узел для проверки, находится ли указанный юнит
 *        (наш персонаж или текущая цель) в состоянии боя.
 */
class IsInCombatCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param source Кто является целью проверки (мы или наша цель).
     * @param mustBeInCombat Если true, узел вернет Success при НАХОЖДЕНИИ в бою.
     *                       Если false, узел вернет Success при ОТСУТСТВИИ боя.
     */
    IsInCombatCondition(UnitSource source, bool mustBeInCombat = true);

    NodeStatus tick(BTContext& context) override;

   private:
    UnitSource m_source;
    bool m_mustBeInCombat;
};