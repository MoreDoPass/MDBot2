#pragma once

#include "core/BehaviorTree/ConditionNode.h"
#include "core/Bot/Character/Character.h"              // Нужно для доступа к enum RuneType
#include "core/Bot/Behaviors/Shared/ComparisonType.h"  // Нужно для операторов сравнения

/**
 * @class HasRunesCondition
 * @brief Узел-условие, проверяющий наличие необходимого количества рун у Рыцаря Смерти.
 * @details Этот узел является специфичным для класса ДК. Он обращается к методу
 *          Character::getRuneCount, чтобы получить актуальное количество готовых рун
 *          заданного типа, и сравнивает его с требуемым значением.
 *          Расположен в Behaviors/Class/DeathKnight, так как является уникальным
 *          "кирпичиком" поведения для этого класса.
 */
class HasRunesCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param type Тип руны для проверки (Blood, Frost, Unholy).
     * @param amount Требуемое количество рун.
     * @param comparison Оператор сравнения (по умолчанию "больше или равно").
     */
    explicit HasRunesCondition(RuneType type, int amount, ComparisonType comparison = ComparisonType::GreaterOrEqual);

    NodeStatus tick(BTContext& context) override;

   private:
    RuneType m_type;
    int m_amount;
    ComparisonType m_comparison;
};