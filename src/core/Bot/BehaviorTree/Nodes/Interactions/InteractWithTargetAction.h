#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class InteractWithTargetAction
 * @brief Узел-действие, который отдает команду на "правый клик" по текущей цели.
 * @details Вызывает InteractionManager, который отправляет в DLL команду
 *          NativeInteract для вызова прямой функции взаимодействия в клиенте.
 *          Это универсальное действие для сбора, лута, разговора и т.д.
 */
class InteractWithTargetAction : public BTNode
{
   public:
    InteractWithTargetAction();  // Конструктор снова пустой
    NodeStatus tick(BTContext& context) override;
};