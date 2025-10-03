#include "FailNode.h"

NodeStatus FailNode::tick(BTContext& context)
{
    // Этот узел не выполняет никаких действий.
    // Его единственная цель - немедленно сообщить родительскому узлу (Selector, Sequence)
    // о провале, чтобы тот мог продолжить выполнение других веток.
    return NodeStatus::Failure;
}