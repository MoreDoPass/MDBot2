#pragma once

#include "core/BehaviorTree/BTNode.h"

/**
 * @class StartAutoAttackAction
 * @brief Узел-действие, который отправляет команду на начало автоатаки
 *        по текущей цели, находящейся в BTContext.
 */
class StartAutoAttackAction : public BTNode
{
   public:
    /**
     * @brief Конструктор. Не принимает аргументов, так как цель для атаки
     *        всегда берется из BTContext.currentTargetGuid.
     */
    StartAutoAttackAction();

    NodeStatus tick(BTContext& context) override;
};