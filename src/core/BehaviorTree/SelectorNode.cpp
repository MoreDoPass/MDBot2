#include "SelectorNode.h"

SelectorNode::SelectorNode(std::vector<std::unique_ptr<BTNode>> children) : m_children(std::move(children)) {}

NodeStatus SelectorNode::tick(BTContext& context)
{
    for (auto& child : m_children)
    {
        const auto status = child->tick(context);
        if (status != NodeStatus::Failure)
        {
            // Если дочерний узел успешно выполнен или все еще выполняется,
            // мы немедленно возвращаем его статус.
            // Мы переходим к следующему узлу, только если текущий провалился.
            return status;
        }
    }
    // Если мы дошли до конца, значит все дочерние узлы вернули Failure.
    return NodeStatus::Failure;
}