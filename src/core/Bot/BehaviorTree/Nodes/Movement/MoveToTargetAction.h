#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @brief "Навык", который командует боту двигаться к цели,
 *        GUID которой хранится в BTContext.
 */
class MoveToTargetAction : public BTNode
{
   public:
    NodeStatus tick(BTContext& context) override;
};