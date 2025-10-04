#pragma once
#include <memory>

class BTNode;
class BTContext;

/**
 * @class BehaviorTreeBuilder
 * @brief Главная фабрика, отвечающая за сборку итогового дерева поведения.
 * @details Этот класс является единой точкой входа для создания дерева.
 *          Он выступает в роли "дирижера", вызывая специализированные
 *          строители (SystemBuilder, ModuleBuilder, CombatBuilder) и
 *          собирая их результаты в единую структуру с правильными приоритетами.
 */
class BehaviorTreeBuilder
{
   public:
    /**
     * @brief Собирает и возвращает корень итогового дерева поведения.
     * @param context Общий контекст, передаваемый всем строителям и узлам.
     * @return Указатель на корень полностью собранного и готового к запуску дерева.
     */
    static std::unique_ptr<BTNode> build(BTContext& context);
};