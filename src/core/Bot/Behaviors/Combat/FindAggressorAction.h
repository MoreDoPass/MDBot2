#pragma once

#include "core/BehaviorTree/BTNode.h"

/**
 * @class FindAggressorAction
 * @brief Узел-действие, который ищет юнита, атакующего нашего персонажа,
 *        и устанавливает его в качестве текущей цели в BTContext.
 * @details Этот узел является ключевым для начала любой боевой ротации.
 *          Он сканирует видимых юнитов и проверяет, чей 'targetGuid'
 *          совпадает с GUID'ом нашего персонажа.
 */
class FindAggressorAction : public BTNode
{
   public:
    /**
     * @brief Конструктор. Не принимает аргументов, так как цель поиска всегда одна -
     *        найти того, кто атакует нашего персонажа.
     */
    FindAggressorAction();

    NodeStatus tick(BTContext& context) override;
};