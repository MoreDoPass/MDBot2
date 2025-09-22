#include "WhileSuccessDecorator.h"

NodeStatus WhileSuccessDecorator::tick(BTContext& context)
{
    const auto status = m_child->tick(context);

    switch (status)
    {
        case NodeStatus::Success:
            // Главная логика: пока ребенок успешен, мы в процессе "ожидания".
            return NodeStatus::Running;

        case NodeStatus::Failure:
            // Ребенок провалился, значит цикл ожидания успешно завершен.
            return NodeStatus::Success;

        case NodeStatus::Running:
            // Если ребенок сам в процессе, мы тоже в процессе.
            return NodeStatus::Running;
    }

    // На всякий случай
    return status;
}