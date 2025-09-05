#pragma once
#include "BTNode.h"
#include <vector>
#include <memory>

/**
 * @brief Композитный узел, который выполняет дочерние узлы последовательно,
 *        пока один из них не вернет Success или Running.
 * @details Он останавливается и возвращает Success/Running, как только
 *          один из дочерних узлов вернет этот статус. Возвращает Failure,
 *          только если ВСЕ дочерние узлы вернули Failure.
 *          Логика "ИЛИ".
 */
class SelectorNode : public BTNode
{
   public:
    /**
     * @brief Конструктор.
     * @param children Список дочерних узлов.
     */
    explicit SelectorNode(std::vector<std::unique_ptr<BTNode>> children);
    NodeStatus tick(BTContext& context) override;

   private:
    /// @brief Список дочерних узлов, которыми управляет этот узел.
    std::vector<std::unique_ptr<BTNode>> m_children;
};