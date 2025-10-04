#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class FaceTargetAction
 * @brief Узел-действие, который отдает команду на поворот персонажа лицом к текущей цели.
 * @details Этот узел вызывает MovementManager::faceTarget(), который отправляет
 *          команду в DLL для выполнения поворота через внутриигровой механизм CtM.
 */
class FaceTargetAction : public BTNode
{
   public:
    FaceTargetAction();
    NodeStatus tick(BTContext& context) override;
};