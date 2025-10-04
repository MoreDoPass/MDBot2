#pragma once

#include "core/BehaviorTree/ConditionNode.h"
#include "core/Bot/BehaviorTree/Nodes/Shared/UnitSource.h"  // <-- Подключаем наш новый, правильный enum
#include "core/Bot/BehaviorTree/Nodes/Shared/ComparisonType.h"

/**
 * @class IsLevelCondition
 * @brief Универсальный узел, который проверяет уровень указанного юнита
 *        (себя или цели) в соответствии с заданным условием.
 */
class IsLevelCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param source Откуда брать юнита для проверки (Self или CurrentTarget).
     * @param op     Тип сравнения (>=, <, ==).
     * @param level  Уровень, с которым будем сравнивать.
     */
    IsLevelCondition(UnitSource source, ComparisonType op, int level);

    // Основной метод, который будет выполнять всю логику
    NodeStatus tick(BTContext& context) override;

   private:
    UnitSource m_source;  // Инструкция: кого проверять
    ComparisonType m_op;  // Инструкция: как сравнивать
    int m_level;          // Инструкция: с чем сравнивать
};