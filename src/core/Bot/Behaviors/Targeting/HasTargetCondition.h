#pragma once
#include "core/BehaviorTree/ConditionNode.h"

/**
 * @class HasTargetCondition
 * @brief Узел-условие, который проверяет, выбрана ли у бота в данный момент цель.
 * @details Этот узел просто проверяет, является ли поле 'currentTargetGuid'
 *          в контексте дерева отличным от нуля.
 *
 *          Это ключевой "переключатель" для логики, которая должна вести себя
 *          по-разному в зависимости от того, "свободен" ли бот или уже "занят"
 *          работой над конкретной целью.
 */
class HasTargetCondition : public ConditionNode
{
   public:
    HasTargetCondition();
    NodeStatus tick(BTContext& context) override;
};