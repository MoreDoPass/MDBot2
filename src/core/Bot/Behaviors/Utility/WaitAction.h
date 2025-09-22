#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <chrono>

class WaitAction : public BTNode
{
   public:
    explicit WaitAction(float milliseconds);

   protected:
    // ИЗМЕНЕНО: Используем NodeStatus и tick, как в вашем проекте
    NodeStatus tick(BTContext& context) override;

   private:
    float m_waitTimeMs;
    bool m_isWaiting = false;
    std::chrono::time_point<std::chrono::steady_clock> m_startTime;
};