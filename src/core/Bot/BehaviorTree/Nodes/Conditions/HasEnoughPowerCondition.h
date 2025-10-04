// --- НАЧАЛО ФАЙЛА HasEnoughPowerCondition.h ---
#pragma once

#include "core/BehaviorTree/ConditionNode.h"  // ИЗМЕНЕНИЕ: Наследуемся от правильного базового класса
#include "shared/data/enums/PowerType.h"      // Подключаем наш enum

/**
 * @class HasEnoughPowerCondition
 * @brief Узел-условие, который проверяет, достаточно ли у персонажа указанного ресурса.
 * @details Этот узел является универсальным решением для проверки маны, ярости, энергии
 *          и силы рун. Он использует универсальный геттер Character::getCurrentPower.
 */
class HasEnoughPowerCondition : public ConditionNode  // ИЗМЕНЕНИЕ: Наследуемся от ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param type Тип ресурса для проверки (Mana, Rage, etc.).
     * @param requiredAmount Минимальное количество ресурса, необходимое для успеха.
     */
    HasEnoughPowerCondition(PowerType type, uint32_t requiredAmount);

    /**
     * @brief Выполняет проверку ресурса.
     * @param context Общий контекст дерева поведения.
     * @return Success, если текущее количество ресурса >= requiredAmount, иначе Failure.
     */
    NodeStatus tick(BTContext& context) override;  // ИЗМЕНЕНИЕ: Возвращаемый тип теперь NodeStatus

   private:
    PowerType m_powerType;      ///< Тип ресурса, который нужно проверить.
    uint32_t m_requiredAmount;  ///< Необходимое количество ресурса.
};
// --- КОНЕЦ ФАЙЛА HasEnoughPowerCondition.h ---