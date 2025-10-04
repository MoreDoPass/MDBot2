// --- START OF FILE OreGrindModule.h ---
#pragma once
#include "core/BehaviorTree/BTNode.h"
#include "core/BehaviorTree/BTContext.h"
#include <memory>

class OreGrindModule
{
   public:
    /**
     * @brief Собирает дерево поведения для модуля сбора ресурсов.
     * @param context Общий контекст дерева.
     * @param combatBehavior УЖЕ СОБРАННОЕ дерево боевой логики,
     *                     которое этот модуль должен использовать.
     * @return Указатель на корень дерева модуля.
     */
    static std::unique_ptr<BTNode> build(BTContext& context, std::unique_ptr<BTNode> combatBehavior);

   private:
    // --- НАШЕ ПРАВИЛЬНОЕ И ОКОНЧАТЕЛЬНОЕ "ОГЛАВЛЕНИЕ" ---

    static std::unique_ptr<BTNode> createFollowPathBranch(BTContext& context);
    static std::unique_ptr<BTNode> createGatherTargetBranch(BTContext& context);
    static std::unique_ptr<BTNode> createFullGatherCycleBranch(BTContext& context);
    static std::unique_ptr<BTNode> createPanicBranch(BTContext& context);
    static std::unique_ptr<BTNode> createWorkLogicBranch(BTContext& context, std::unique_ptr<BTNode> combatBehavior);
};