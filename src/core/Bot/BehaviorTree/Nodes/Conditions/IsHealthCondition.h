#pragma once

#include "core/BehaviorTree/ConditionNode.h"
#include "core/Bot/BehaviorTree/Nodes/Shared/UnitSource.h"
#include "core/Bot/BehaviorTree/Nodes/Shared/ComparisonType.h"

/**
 * @enum HealthCheckType
 * @brief Определяет, какой аспект здоровья юнита будет проверяться.
 */
enum class HealthCheckType
{
    /**
     * @brief Проверка текущего здоровья в процентах от максимального.
     * @details Пример: "здоровье цели < 20%".
     */
    Percentage,

    /**
     * @brief Проверка абсолютного (числового) значения текущего здоровья.
     * @details Пример: "мое здоровье > 1000".
     */
    Absolute,

    /**
     * @brief Проверка количества недостающего здоровья (maxHealth - currentHealth).
     * @details Крайне полезно для "умного" лечения, чтобы не перелечивать (оверхилить).
     *          Пример: "недостающее здоровье > 500".
     */
    Missing
};

/**
 * @class IsHealthCondition
 * @brief Универсальный узел-условие для проверки состояния здоровья юнита.
 * @details Этот узел является мощным инструментом, который заменяет собой
 *          несколько более специализированных узлов. Он может проверять здоровье
 *          в процентах, в абсолютных значениях или количество недостающего
 *          здоровья, что делает его применимым как в боевых ротациях (для
 *          добивающих способностей), так и в логике поддержки (для лечения).
 */
class IsHealthCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param source Чье здоровье проверять (нашего персонажа или цели).
     * @param comparison Тип сравнения (меньше, больше, равно и т.д.).
     * @param checkType Как именно проверять здоровье (проценты, абсолютное и т.д.).
     * @param value Значение, с которым будет производиться сравнение.
     */
    explicit IsHealthCondition(UnitSource source, ComparisonType comparison, HealthCheckType checkType, float value);

    NodeStatus tick(BTContext& context) override;

   private:
    UnitSource m_source;
    ComparisonType m_comparison;
    HealthCheckType m_checkType;
    float m_value;
};