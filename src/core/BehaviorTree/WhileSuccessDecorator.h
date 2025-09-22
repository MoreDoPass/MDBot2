#pragma once
#include "DecoratorNode.h"

/**
 * @class WhileSuccessDecorator
 * @brief Декоратор, который повторяет выполнение дочернего узла, пока тот возвращает Success.
 * @details Этот узел используется для создания циклов ожидания.
 *
 * - Если дочерний узел возвращает Success, декоратор вернет Running (продолжаем ждать).
 * - Если дочерний узел возвращает Failure, декоратор вернет Success (ожидание завершено).
 * - Если дочерний узел возвращает Running, декоратор вернет Running.
 */
class WhileSuccessDecorator : public DecoratorNode
{
   public:
    /**
     * @brief Конструктор.
     * @param child Единственный дочерний узел, который будет выполняться в цикле.
     */
    explicit WhileSuccessDecorator(std::unique_ptr<BTNode> child) : DecoratorNode(std::move(child)) {}
    NodeStatus tick(BTContext& context) override;
};