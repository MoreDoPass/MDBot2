#include "SequenceNode.h"

SequenceNode::SequenceNode(std::vector<std::unique_ptr<BTNode>> children) : m_children(std::move(children)) {}

NodeStatus SequenceNode::tick(BTContext& context)
{
    for (auto& child : m_children)
    {
        const auto status = child->tick(context);
        if (status != NodeStatus::Success)
        {
            // Если дочерний узел провалился или все еще выполняется,
            // мы немедленно возвращаем его статус и не идем дальше.
            return status;
        }
    }
    // Если мы дошли до конца, значит все дочерние узлы вернули Success.
    return NodeStatus::Success;
}