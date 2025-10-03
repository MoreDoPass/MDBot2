#include "PartyModule.h"
#include "core/BehaviorTree/SequenceNode.h"  // Просто для примера

std::unique_ptr<BTNode> PartyModule::build(BTContext& context)
{
    // ПОКА ЧТО ЭТА ИНСТРУКЦИЯ НИЧЕГО НЕ ДЕЛАЕТ.
    // Она сразу говорит "я закончил", чтобы управление перешло
    // к следующему модулю (например, гринду).
    // Позже мы наполним ее логикой.
    return nullptr;  // nullptr или пустой узел означает мгновенный провал (Failure)
}