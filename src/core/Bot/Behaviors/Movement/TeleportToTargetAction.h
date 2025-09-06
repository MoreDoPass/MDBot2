#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class TeleportToTargetAction
 * @brief "Навык", который командует боту телепортироваться к цели,
 *        GUID которой хранится в BTContext.
 * @details В отличие от MoveTo, этот навык считается мгновенным, если телепортация
 *          прошла успешно (возвращает Success), либо провальным (Failure).
 *          Он не возвращает статус Running.
 */
class TeleportToTargetAction : public BTNode
{
   public:
    NodeStatus tick(BTContext& context) override;
};