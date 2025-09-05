#pragma once
#include "BTNode.h"
#include <memory>

/**
 * @brief Абстрактный базовый класс для всех узлов-декораторов.
 * @details Декоратор — это узел-обертка, который имеет ровно одного
 *          дочернего узла и каким-либо образом изменяет его поведение
 *          или результат его работы.
 */
class DecoratorNode : public BTNode
{
   public:
    /**
     * @brief Конструктор.
     * @param child Единственный дочерний узел.
     */
    explicit DecoratorNode(std::unique_ptr<BTNode> child) : m_child(std::move(child)) {}

   protected:
    /// @brief Указатель на единственного дочернего узла.
    std::unique_ptr<BTNode> m_child;
};