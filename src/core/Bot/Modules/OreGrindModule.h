#pragma once
#include "core/BehaviorTree/BTNode.h"
#include "core/BehaviorTree/BTContext.h"  // <-- ИЗМЕНЕНО
#include <memory>

class OreGrindModule
{
   public:
    /**
     * @brief Собирает дерево поведения для модуля сбора ресурсов.
     * @param context Полный контекст, содержащий настройки и менеджеры.
     * @return Указатель на корень собранного дерева.
     */
    static std::unique_ptr<BTNode> build(BTContext& context);  // <-- ИЗМЕНЕНО
};