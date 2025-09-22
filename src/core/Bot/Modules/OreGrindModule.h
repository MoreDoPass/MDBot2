// --- START OF FILE OreGrindModule.h ---
#pragma once
#include "core/BehaviorTree/BTNode.h"
#include "core/BehaviorTree/BTContext.h"
#include <memory>

class OreGrindModule
{
   public:
    static std::unique_ptr<BTNode> build(BTContext& context);

   private:
    // --- НАШЕ ПРАВИЛЬНОЕ И ОКОНЧАТЕЛЬНОЕ "ОГЛАВЛЕНИЕ" ---

    static std::unique_ptr<BTNode> createFollowPathBranch(BTContext& context);
    static std::unique_ptr<BTNode> createGatherTargetBranch(BTContext& context);
    // НОВАЯ, основная ветка для всего цикла сбора
    static std::unique_ptr<BTNode> createFullGatherCycleBranch(BTContext& context);
    static std::unique_ptr<BTNode> createPanicBranch(BTContext& context);
    static std::unique_ptr<BTNode> createWorkLogicBranch(BTContext& context);
};