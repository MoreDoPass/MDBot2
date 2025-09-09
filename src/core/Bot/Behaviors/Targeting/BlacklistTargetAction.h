// ФАЙЛ: src/core/Bot/Behaviors/Targeting/BlacklistTargetAction.h

#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class BlacklistTargetAction
 * @brief "Навык", который добавляет текущую цель из контекста во временный черный список.
 * @details Этот узел используется, когда попытка взаимодействия с целью провалилась
 *          из-за внешних факторов (например, присутствие других игроков). Он всегда
 *          возвращает Failure, чтобы прервать текущую ветку дерева поведения.
 */
class BlacklistTargetAction : public BTNode
{
   public:
    /**
     * @brief Конструктор.
     * @param durationSeconds Длительность в секундах, на которую цель будет добавлена в черный список.
     */
    explicit BlacklistTargetAction(int durationSeconds = 120);
    NodeStatus tick(BTContext& context) override;

   private:
    /// @brief Длительность блокировки цели в секундах.
    int m_durationSeconds;
};