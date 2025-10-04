#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class FollowPathAction
 * @brief Управляет движением по маршруту из профиля.
 * @details Этот узел проверяет, не достиг ли бот текущей точки маршрута.
 *          Если достиг, переключается на следующую. Затем он записывает
 *          координаты текущей целевой точки в context.currentTargetPosition.
 *          Этот узел ВСЕГДА возвращает Success, т.к. его задача - только
 *          установить цель, а не дойти до нее.
 */
class FollowPathAction : public BTNode
{
   public:
    NodeStatus tick(BTContext& context) override;
};