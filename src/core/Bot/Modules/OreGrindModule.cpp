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
#include "core/Bot/Behaviors/Interactions/InteractWithTargetAction.h"
#include "core/Bot/Behaviors/Conditions/IsCastingCondition.h"
#include "core/BehaviorTree/WhileSuccessDecorator.h"
#include "core/Bot/Behaviors/Targeting/HasTargetCondition.h"
#include "core/Bot/Behaviors/Targeting/ClearTargetAction.h"
#include "core/Bot/Behaviors/Conditions/IsInRangeCondition.h"
#include "core/Bot/Behaviors/Utility/WaitAction.h"
#include <vector>

#include "core/Bot/CombatLogic/Paladin/RetributionBuilder.h"

// --- ИЗМЕНЕНИЕ: Упрощаем эту функцию ---
// Теперь она не содержит никакой логики, кроме выбора типа движения.
// Проверки на игроков будут делаться в самом дереве.
static std::unique_ptr<BTNode> createMovementNode(BTContext& context)
{
    const auto& movementSettings = context.settings.movementSettings;

    if (movementSettings.navigationType == MovementSettings::NavigationType::Teleport_Only)
    {
        return std::make_unique<TeleportToTargetAction>(3.0f);
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
            children.push_back(std::make_unique<TeleportToTargetAction>(3.0f));
            selectorChildren.push_back(std::make_unique<SequenceNode>(std::move(children)));
        }
        selectorChildren.push_back(std::make_unique<MoveToTargetAction>());
        return std::make_unique<SelectorNode>(std::move(selectorChildren));
    }

    // По умолчанию просто бежим
    return std::make_unique<MoveToTargetAction>();
}

// Ветка: лететь по маршруту. Это Sequence: Шаг 1 И Шаг 2 И Шаг 3.
std::unique_ptr<BTNode> OreGrindModule::createFollowPathBranch(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;
    children.push_back(std::make_unique<FollowPathAction>());
    children.push_back(std::make_unique<ModifyTargetZAction>(150.0f));
    children.push_back(createMovementNode(context));
    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> OreGrindModule::createGatherTargetBranch(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;

    // Шаг 1: Подлететь к цели (если еще не там)
    children.push_back(createMovementNode(context));
    // Шаг 2: Убедиться, что мы вплотную
    children.push_back(std::make_unique<IsInRangeCondition>(4.0f));

    // --- НОВОЕ КЛЮЧЕВОЕ УСЛОВИЕ ---
    // Шаг 3: Продолжать, только если мы НЕ кастуем.
    // IsCastingCondition вернет Success, если мы кастуем -> Inverter превратит это в Failure.
    // IsCastingCondition вернет Failure, если мы НЕ кастуем -> Inverter превратит это в Success.
    children.push_back(std::make_unique<InverterNode>(std::make_unique<IsCastingCondition>(UnitSource::Self)));

    // Шаг 4: Отправить команду на взаимодействие (выполнится, только если прошли Шаг 3)
    children.push_back(std::make_unique<InteractWithTargetAction>());
    children.push_back(std::make_unique<WaitAction>(1250.0f));
    // Шаг 5: Ждать, пока каст не ЗАКОНЧИТСЯ
    children.push_back(std::make_unique<WhileSuccessDecorator>(std::make_unique<IsCastingCondition>(UnitSource::Self)));

    // Шаг 7: Очистить цель
    children.push_back(std::make_unique<ClearTargetAction>());
    // Шаг 8: Пауза, чтобы руда-призрак исчезла
    children.push_back(std::make_unique<WaitAction>(250.0f));

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> OreGrindModule::createFullGatherCycleBranch(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> selectorChildren;
    {
        std::vector<std::unique_ptr<BTNode>> sequenceChildren;
        sequenceChildren.push_back(std::make_unique<HasTargetCondition>(GameObjectType::GameObject));
        // ИСПРАВЛЕНО: Правильно вызываем статический метод
        sequenceChildren.push_back(OreGrindModule::createGatherTargetBranch(context));
        selectorChildren.push_back(std::make_unique<SequenceNode>(std::move(sequenceChildren)));
    }
    selectorChildren.push_back(
        std::make_unique<FindObjectByIdAction>(context.settings.gatheringSettings.nodeIdsToGather));
    return std::make_unique<SelectorNode>(std::move(selectorChildren));
}

std::unique_ptr<BTNode> OreGrindModule::createPanicBranch(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;
    children.push_back(std::make_unique<IsPlayersNearbyCondition>());
    // ИСПРАВЛЕНО: Правильно вызываем статический метод
    children.push_back(OreGrindModule::createFollowPathBranch(context));
    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> OreGrindModule::createWorkLogicBranch(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;
    children.push_back(RetributionBuilder::buildCombatTree(context));
    // ИСПРАВЛЕНО: Правильно вызываем статический метод
    children.push_back(OreGrindModule::createFullGatherCycleBranch(context));
    // ИСПРАВЛЕНО: Правильно вызываем статический метод
    children.push_back(OreGrindModule::createFollowPathBranch(context));
    return std::make_unique<SelectorNode>(std::move(children));
}

// --- ГЛАВНЫЙ МЕТОД BUILD ---
std::unique_ptr<BTNode> OreGrindModule::build(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(std::make_unique<LoadGatheringProfileAction>());
    {
        std::vector<std::unique_ptr<BTNode>> mainSelectorChildren;
        // ИСПРАВЛЕНО: Правильно вызываем статический метод
        mainSelectorChildren.push_back(OreGrindModule::createPanicBranch(context));
        // ИСПРАВЛЕНО: Правильно вызываем статический метод
        mainSelectorChildren.push_back(OreGrindModule::createWorkLogicBranch(context));
        rootChildren.push_back(std::make_unique<SelectorNode>(std::move(mainSelectorChildren)));
    }
    return std::make_unique<SequenceNode>(std::move(rootChildren));
}