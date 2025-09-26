#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class TeleportToTargetAction
 * @brief Умный "навык", который телепортирует персонажа к цели.
 * @details Может телепортировать как в точную позицию цели, так и на
 *          указанное расстояние от нее, двигаясь по прямой линии от
 *          персонажа к цели. Это позволяет избегать телепортации "внутрь"
 *          модели и сразу занимать удобную позицию для атаки.
 */
class TeleportToTargetAction : public BTNode
{
   public:
    /**
     * @brief Конструктор для телепортации на дистанцию от цели.
     * @param offsetDistance Расстояние в ярдах, на котором нужно остановиться
     *                       от цели. Если 0.0f, телепортация произойдет в
     *                       точную позицию цели.
     */
    explicit TeleportToTargetAction(float offsetDistance = 0.0f);

    NodeStatus tick(BTContext& context) override;

   private:
    /// @brief Дистанция, которую нужно "не долететь" до цели.
    float m_offsetDistance;
};