#include "OreGrindModule.h"
#include "core/BehaviorTree/SequenceNode.h"
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/InverterNode.h"
#include "core/Bot/Behaviors/Targeting/FindObjectByIdAction.h"
#include "core/Bot/Behaviors/Movement/MoveToTargetAction.h"
#include "core/Bot/Behaviors/Movement/TeleportToTargetAction.h"      // <-- НОВЫЙ ИНКЛЮД
#include "core/Bot/Behaviors/Conditions/IsPlayersNearbyCondition.h"  // <-- НОВЫЙ ИНКЛЮД
#include "core/Bot/Behaviors/Profiles/LoadGatheringProfileAction.h"

#include <vector>

// Теперь эта функция принимает контекст, т.к. ей нужны настройки
static std::unique_ptr<BTNode> createMovementNode(BTContext& context)
{
    const auto& movementSettings = context.settings.movementSettings;

    if (movementSettings.navigationType == MovementSettings::NavigationType::CtM_Only)
    {
        return std::make_unique<MoveToTargetAction>();
    }

    if (movementSettings.navigationType == MovementSettings::NavigationType::CtM_And_Teleport)
    {
        std::vector<std::unique_ptr<BTNode>> selectorChildren;
        {
            std::vector<std::unique_ptr<BTNode>> children;
            children.push_back(std::make_unique<InverterNode>(std::make_unique<IsPlayersNearbyCondition>()));
            children.push_back(std::make_unique<TeleportToTargetAction>());
            selectorChildren.push_back(std::make_unique<SequenceNode>(std::move(children)));
        }
        selectorChildren.push_back(std::make_unique<MoveToTargetAction>());
        return std::make_unique<SelectorNode>(std::move(selectorChildren));
    }

    if (movementSettings.navigationType == MovementSettings::NavigationType::Teleport_Only)
    {
        std::vector<std::unique_ptr<BTNode>> children;
        children.push_back(std::make_unique<InverterNode>(std::make_unique<IsPlayersNearbyCondition>()));
        children.push_back(std::make_unique<TeleportToTargetAction>());
        return std::make_unique<SequenceNode>(std::move(children));
    }

    return std::make_unique<MoveToTargetAction>();
}

std::unique_ptr<BTNode> OreGrindModule::build(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;

    // Шаг 0: Загрузить профиль
    children.push_back(std::make_unique<LoadGatheringProfileAction>());

    // Шаг 1: Найти ближайший объект (теперь ID берутся из контекста, который обновил LoadProfileAction)
    children.push_back(std::make_unique<FindObjectByIdAction>(context.settings.gatheringSettings.nodeIdsToGather));

    // Шаг 2: Двигаться к найденной цели
    children.push_back(createMovementNode(context));

    // TODO: Шаг 3: Собрать ресурс
    // TODO: Шаг 4: Двигаться по маршруту из профиля (новый узел FollowPathNode)

    return std::make_unique<SequenceNode>(std::move(children));
}