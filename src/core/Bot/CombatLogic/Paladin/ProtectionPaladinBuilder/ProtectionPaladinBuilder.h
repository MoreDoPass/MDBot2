#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <memory>

class BTContext;

/**
 * @class RetributionBuilder
 * @brief Собирает дерево боевого поведения для паладина "Воздаяние".
 */
class ProtectionPaladinBuilder
{
   public:
    // Главный метод, который соберет всю логику для спека.
    static std::unique_ptr<BTNode> buildCombatTree(BTContext& context);

   private:
    // Вспомогательный метод для логики ВНЕ боя (баффы и подготовка)
    static std::unique_ptr<BTNode> buildOutOfCombatLogic(BTContext& context);

    // Вспомогательный метод для логики ВНУТРИ боя (пока оставим пустым)
    static std::unique_ptr<BTNode> buildInCombatLogic(BTContext& context);
};