#pragma once

#include "core/BehaviorTree/BTNode.h"

/**
 * @class FailNode
 * @brief Простой узел-действие, который ничего не делает и всегда возвращает Failure.
 * @details Идеально подходит для использования в качестве "узла-пустышки" или заглушки,
 *          когда нужно вернуть валидный узел, который гарантированно провалит
 *          выполнение ветки дерева.
 */
class FailNode : public BTNode
{
   public:
    /**
     * @brief Выполняет "тик" узла.
     * @param context Контекст дерева поведения (не используется).
     * @return Всегда возвращает BTStatus::Failure.
     */
    NodeStatus tick(BTContext& context) override;
};