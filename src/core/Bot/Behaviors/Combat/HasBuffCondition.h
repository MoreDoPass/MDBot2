#pragma once

#include "core/BehaviorTree/ConditionNode.h"
#include "core/Bot/Behaviors/Shared/UnitSource.h"

/**
 * @class HasBuffCondition
 * @brief Универсальный узел для проверки наличия или отсутствия ауры (баффа/дебаффа)
 *        на указанной цели.
 */
class HasBuffCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param target Кто является целью проверки (мы или наша цель).
     * @param auraId ID ауры (баффа или дебаффа) для поиска.
     * @param mustBePresent Если true, узел вернет Success при НАЛИЧИИ ауры.
     *                      Если false, узел вернет Success при ОТСУТСТВИИ ауры.
     */
    HasBuffCondition(UnitSource target, int auraId, bool mustBePresent = true);

    // Основной метод, который будет реализован в .cpp файле
    NodeStatus tick(BTContext& context) override;

   private:
    UnitSource m_target;
    int m_auraId;
    bool m_mustBePresent;
};