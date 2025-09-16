// ФАЙЛ: src/core/Bot/Modules/OreGrindModule.cpp

#include "OreGrindModule.h"
#include "core/BehaviorTree/SequenceNode.h"
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/InverterNode.h"
#include "core/Bot/Behaviors/Targeting/FindObjectByIdAction.h"
#include "core/Bot/Behaviors/Targeting/BlacklistTargetAction.h"
#include "core/Bot/Behaviors/Movement/MoveToTargetAction.h"
#include "core/Bot/Behaviors/Movement/TeleportToTargetAction.h"
#include "core/Bot/Behaviors/Conditions/IsPlayersNearbyCondition.h"
#include "core/Bot/Behaviors/Profiles/LoadGatheringProfileAction.h"
#include "core/Bot/Behaviors/Movement/FollowPathAction.h"
#include "core/Bot/Behaviors/Movement/ModifyTargetZAction.h"
#include <vector>

// --- ИЗМЕНЕНИЕ: Упрощаем эту функцию ---
// Теперь она не содержит никакой логики, кроме выбора типа движения.
// Проверки на игроков будут делаться в самом дереве.
static std::unique_ptr<BTNode> createMovementNode(BTContext& context)
{
    const auto& movementSettings = context.settings.movementSettings;

    if (movementSettings.navigationType == MovementSettings::NavigationType::Teleport_Only)
    {
        return std::make_unique<TeleportToTargetAction>();
    }
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

    // По умолчанию просто бежим
    return std::make_unique<MoveToTargetAction>();
}

std::unique_ptr<BTNode> OreGrindModule::build(BTContext& context)
{
    // --- Ветка №1 (Приоритет ВЫСОКИЙ): Попытка найти и собрать руду ---
    std::vector<std::unique_ptr<BTNode>> attemptGatherBranchChildren;

    // 1. Найти руду (которая не в черном списке)
    attemptGatherBranchChildren.push_back(
        std::make_unique<FindObjectByIdAction>(context.settings.gatheringSettings.nodeIdsToGather));

    // 2. "Развилка": что делать с найденной целью? Используем Selector.
    {
        std::vector<std::unique_ptr<BTNode>> choiceChildren;
        // 2a. (Приоритет ВЫШЕ): Если путь свободен, летим собирать.
        {
            std::vector<std::unique_ptr<BTNode>> gatherIfSafeChildren;
            // Условие: рядом НЕТ игроков. Inverter превращает Success от IsPlayersNearby в Failure и наоборот.
            gatherIfSafeChildren.push_back(
                std::make_unique<InverterNode>(std::make_unique<IsPlayersNearbyCondition>()));
            // Действие: Двигаться к цели
            gatherIfSafeChildren.push_back(createMovementNode(context));
            // TODO: Действие: Собрать руду
            // gatherIfSafeChildren.push_back(std::make_unique<GatherAction>());
            choiceChildren.push_back(std::make_unique<SequenceNode>(std::move(gatherIfSafeChildren)));
        }

        // 2b. (Приоритет НИЖЕ): Если предыдущая ветка не сработала (значит, игроки ЕСТЬ),
        //     то заносим цель в черный список. Этот узел вернет Failure, что заставит
        //     провалиться всю ветку attemptGatherBranch.
        choiceChildren.push_back(std::make_unique<BlacklistTargetAction>(120));

        attemptGatherBranchChildren.push_back(std::make_unique<SelectorNode>(std::move(choiceChildren)));
    }
    auto attemptGatherBranch = std::make_unique<SequenceNode>(std::move(attemptGatherBranchChildren));

    // --- Ветка №2 (Приоритет НИЗКИЙ): Движение по маршруту ПОД ЗЕМЛЕЙ ---
    // Выполняется, если attemptGatherBranch вернула Failure.
    std::vector<std::unique_ptr<BTNode>> followPathChildren;
    followPathChildren.push_back(std::make_unique<FollowPathAction>());
    followPathChildren.push_back(std::make_unique<ModifyTargetZAction>(150.0f));
    followPathChildren.push_back(createMovementNode(context));
    auto followPathBranch = std::make_unique<SequenceNode>(std::move(followPathChildren));

    // "Менеджер-Прагматик" (Selector), который управляет ветками
    std::vector<std::unique_ptr<BTNode>> mainLogicChildren;
    mainLogicChildren.push_back(std::move(attemptGatherBranch));  // Сначала попробуй найти и собрать
    mainLogicChildren.push_back(std::move(followPathBranch));     // Если не вышло - лети к следующей точке
    auto mainLogic = std::make_unique<SelectorNode>(std::move(mainLogicChildren));

    // Корневой узел
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(std::make_unique<LoadGatheringProfileAction>());
    rootChildren.push_back(std::move(mainLogic));

    return std::make_unique<SequenceNode>(std::move(rootChildren));
}