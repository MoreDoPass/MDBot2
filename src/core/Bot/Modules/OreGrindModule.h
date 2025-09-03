#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <memory>

class OreGrindModule
{  // <-- Имя изменено
   public:
    static std::unique_ptr<BTNode> build();
};