#pragma once

#include "core/BehaviorTree/ConditionNode.h"
#include "core/Bot/BehaviorTree/Nodes/Shared/UnitSource.h"

/**
 * @class IsCastingCondition
 * @brief Универсальный узел для проверки, кастует ли указанный юнит
 *        (наш персонаж или текущая цель) какое-либо заклинание.
 * @details Этот "датчик" обращается к GameObjectManager, который получает актуальные
 *          данные о касте из DLL. Узел можно настроить на проверку как самого
 *          факта каста, так и на проверку каста конкретного заклинания.
 */
class IsCastingCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param source Кто является целью проверки (мы или наша цель).
     * @param spellId (Опционально) ID заклинания для проверки. Если 0, узел будет проверять
     *                любой каст. Если указан ID, узел вернет Success только
     *                если юнит кастует именно это заклинание.
     * @param mustBeCasting Если true, узел вернет Success при НАЛИЧИИ каста.
     *                      Если false, узел вернет Success при ОТСУТСТВИИ каста.
     */
    IsCastingCondition(UnitSource source, int spellId = 0, bool mustBeCasting = true);

    NodeStatus tick(BTContext& context) override;

   private:
    UnitSource m_source;
    int m_spellId;
    bool m_mustBeCasting;
};