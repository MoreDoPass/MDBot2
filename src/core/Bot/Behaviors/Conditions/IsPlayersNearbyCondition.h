// МЕСТОПОЛОЖЕНИЕ: src/core/Bot/Behaviors/Conditions/IsPlayersNearbyCondition.h

#pragma once
#include "core/BehaviorTree/ConditionNode.h"

/**
 * @brief "Условие", которое проверяет, есть ли другие игроки рядом с персонажем.
 * @details Логика основана на простом предположении: если в списке видимых
 *          объектов типа "Игрок" находится больше одного элемента, значит,
 *          помимо нашего персонажа, есть кто-то еще.
 */
class IsPlayersNearbyCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param checkRadius Этот параметр пока не используется в упрощенной логике,
     *                    но зарезервирован для будущих усложнений (например,
     *                    проверки дистанции до других игроков).
     */
    explicit IsPlayersNearbyCondition(float checkRadius = 50.0f);
    NodeStatus tick(BTContext& context) override;

   private:
    /// @brief Радиус для проверки (пока не используется, задел на будущее).
    float m_checkRadius;
};