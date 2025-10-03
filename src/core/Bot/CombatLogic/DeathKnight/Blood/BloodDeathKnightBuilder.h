#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <memory>

class BTContext;

/**
 * @class BloodDeathKnightBuilder
 * @brief Собирает дерево боевого поведения для Рыцаря Смерти "Кровь".
 */
class BloodDeathKnightBuilder

{
   public:
    // Главный метод, который соберет всю логику для спека.
    static std::unique_ptr<BTNode> buildCombatTree(BTContext& context);

   private:
    // Вспомогательный метод для логики ВНЕ боя (баффы и подготовка)
    static std::unique_ptr<BTNode> buildOutOfCombatLogic(BTContext& context);

    // Вспомогательный метод для логики ВНУТРИ боя (пока оставим пустым)
    static std::unique_ptr<BTNode> buildInCombatLogic(BTContext& context);

    /**
     * @brief Собирает ветку для использования Удара в Сердце.
     */
    static std::unique_ptr<BTNode> buildHeartStrikeBranch(BTContext& context);

    /**
     * @brief Собирает ветку для использования Пожинания (Reap) - кастомный скилл.
     * @details Скилл не имеет рангов. Требует уровень >= 60.
     * @param context Контекст дерева.
     * @return Указатель на узел SequenceNode.
     */
    static std::unique_ptr<BTNode> buildReapBranch(BTContext& context);
};