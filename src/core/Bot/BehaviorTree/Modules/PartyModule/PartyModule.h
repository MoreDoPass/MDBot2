#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <memory>

class BTContext;

// Наша новая "инструкция", которая будет отвечать за сбор группы,
// ребаффы, следование за лидером и т.д.
class PartyModule
{
   public:
    static std::unique_ptr<BTNode> build(BTContext& context);
};