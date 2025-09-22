#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class ClearTargetAction
 * @brief Простейший узел-действие, который очищает текущую цель бота.
 * @details Его единственная задача — обнулить поле 'currentTargetGuid' в контексте
 *          дерева. Это позволяет боту "отпустить" текущую цель после завершения
 *          работы с ней и стать готовым к поиску новой цели.
 *
 *          Всегда возвращает Success.
 */
class ClearTargetAction : public BTNode
{
   public:
    ClearTargetAction();
    NodeStatus tick(BTContext& context) override;
};