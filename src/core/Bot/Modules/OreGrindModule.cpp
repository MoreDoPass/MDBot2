#include "OreGrindModule.h"
#include "core/BehaviorTree/SequenceNode.h"
#include "core/Bot/Behaviors/Targeting/FindObjectByIdAction.h"
#include "core/Bot/Behaviors/Movement/MoveToTargetAction.h"

std::unique_ptr<BTNode> OreGrindModule::build(const BotStartSettings& settings)
{
    std::vector<std::unique_ptr<BTNode>> children;

    // Шаг 1: Найти ближайший объект из списка ID, который пришел из GUI.
    children.push_back(std::make_unique<FindObjectByIdAction>(settings.gatheringSettings.nodeIdsToGather));

    // Шаг 2: Двигаться к найденной цели.
    children.push_back(std::make_unique<MoveToTargetAction>());

    return std::make_unique<SequenceNode>(std::move(children));
}