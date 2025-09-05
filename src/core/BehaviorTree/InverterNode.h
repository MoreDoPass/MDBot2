#pragma once
#include "DecoratorNode.h"

/**
 * @brief Декоратор, который инвертирует результат своего дочернего узла.
 * @details
 * - Если дочерний узел возвращает Success, Inverter вернет Failure.
 * - Если дочерний узел возвращает Failure, Inverter вернет Success.
 * - Если дочерний узел возвращает Running, Inverter вернет Running.
 *   Логика "НЕ".
 */
class InverterNode : public DecoratorNode
{
   public:
    /**
     * @brief Конструктор.
     * @param child Единственный дочерний узел, результат которого будет инвертирован.
     */
    explicit InverterNode(std::unique_ptr<BTNode> child) : DecoratorNode(std::move(child)) {}
    NodeStatus tick(BTContext& context) override;
};