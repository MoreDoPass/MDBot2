#pragma once
#include "BTNode.h"
#include <vector>
#include <memory>

/**
 * @brief Композитный узел, который выполняет дочерние узлы последовательно.
 * @details Он останавливается и возвращает Failure/Running, как только
 *          один из дочерних узлов вернет этот статус. Возвращает Success,
 *          только если ВСЕ дочерние узлы вернули Success.
 *          Логика "И".
 */
class SequenceNode : public BTNode
{
   public:
    explicit SequenceNode(std::vector<std::unique_ptr<BTNode>> children);
    NodeStatus tick(BTContext& context) override;

   private:
    std::vector<std::unique_ptr<BTNode>> m_children;
};