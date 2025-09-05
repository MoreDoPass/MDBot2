#include "InverterNode.h"

NodeStatus InverterNode::tick(BTContext& context)
{
    const auto status = m_child->tick(context);

    switch (status)
    {
        case NodeStatus::Success:
            // Успех дочернего узла — это провал для инвертора.
            return NodeStatus::Failure;
        case NodeStatus::Failure:
            // Провал дочернего узла — это успех для инвертора.
            return NodeStatus::Success;
        case NodeStatus::Running:
            // Статус Running не изменяется.
            return NodeStatus::Running;
    }

    // На всякий случай, если появятся новые статусы.
    return status;
}