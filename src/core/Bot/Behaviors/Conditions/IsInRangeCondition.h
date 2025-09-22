#pragma once
#include "core/BehaviorTree/ConditionNode.h"

/**
 * @class IsInRangeCondition
 * @brief Узел-условие, который проверяет, находится ли персонаж на указанном
 *        расстоянии (или ближе) от своей текущей цели.
 * @details Этот узел необходим для точных действий, таких как взаимодействие
 *          с объектами или применение способностей ближнего боя. Он сравнивает
 *          квадрат расстояния, чтобы избежать дорогостоящей операции
 *          извлечения квадратного корня на каждом тике.
 */
class IsInRangeCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param distance Максимально допустимое расстояние до цели в ярдах.
     */
    explicit IsInRangeCondition(float distance);

    NodeStatus tick(BTContext& context) override;

   private:
    /// @brief Квадрат максимального расстояния для эффективного сравнения.
    float m_distanceSq;
};