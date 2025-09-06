#include "OreGrindModule.h"
#include "core/BehaviorTree/SequenceNode.h"
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/InverterNode.h"
#include "core/Bot/Behaviors/Targeting/FindObjectByIdAction.h"
#include "core/Bot/Behaviors/Movement/MoveToTargetAction.h"
#include "core/Bot/Behaviors/Movement/TeleportToTargetAction.h"      // <-- НОВЫЙ ИНКЛЮД
#include "core/Bot/Behaviors/Conditions/IsPlayersNearbyCondition.h"  // <-- НОВЫЙ ИНКЛЮД

static std::unique_ptr<BTNode> createMovementNode(const BotStartSettings& settings)
{
    const auto& movementSettings = settings.movementSettings;

    if (movementSettings.navigationType == MovementSettings::NavigationType::CtM_Only)
    {
        return std::make_unique<MoveToTargetAction>();
    }

    if (movementSettings.navigationType == MovementSettings::NavigationType::CtM_And_Teleport)
    {
        // --- ИЗМЕНЕНИЕ ЗДЕСЬ: Создаем вектор и узлы по-старинке ---

        // 1. Создаем пустой вектор для дочерних узлов Selector'а
        std::vector<std::unique_ptr<BTNode>> selectorChildren;

        // 2. Создаем ветку для телепортации (Sequence)
        {  // Ограничиваем область видимости, чтобы случайно не использовать children отсюда
            std::vector<std::unique_ptr<BTNode>> children;
            children.push_back(std::make_unique<InverterNode>(std::make_unique<IsPlayersNearbyCondition>()));
            children.push_back(std::make_unique<TeleportToTargetAction>());

            // Добавляем готовую ветку в наш главный вектор. std::move обязателен.
            selectorChildren.push_back(std::make_unique<SequenceNode>(std::move(children)));
        }

        // 3. Добавляем вторую ветку - обычное движение
        selectorChildren.push_back(std::make_unique<MoveToTargetAction>());

        // 4. Создаем Selector, передавая ему готовый и правильно заполненный вектор
        return std::make_unique<SelectorNode>(std::move(selectorChildren));
    }

    if (movementSettings.navigationType == MovementSettings::NavigationType::Teleport_Only)
    {
        // --- ИЗМЕНЕНИЕ ЗДЕСЬ: Та же логика, что и выше ---
        std::vector<std::unique_ptr<BTNode>> children;
        children.push_back(std::make_unique<InverterNode>(std::make_unique<IsPlayersNearbyCondition>()));
        children.push_back(std::make_unique<TeleportToTargetAction>());
        return std::make_unique<SequenceNode>(std::move(children));
    }

    return std::make_unique<MoveToTargetAction>();
}

std::unique_ptr<BTNode> OreGrindModule::build(const BotStartSettings& settings)
{
    std::vector<std::unique_ptr<BTNode>> children;

    // Шаг 1: Найти ближайший объект из списка ID (без изменений)
    children.push_back(std::make_unique<FindObjectByIdAction>(settings.gatheringSettings.nodeIdsToGather));

    // Шаг 2: Двигаться к найденной цели (теперь вызываем нашу умную функцию-конструктор)
    children.push_back(createMovementNode(settings));

    // TODO: Шаг 3: Собрать ресурс (будет добавлен позже)
    // children.push_back(std::make_unique<GatherNodeAction>());

    // TODO: Шаг 4 (для режима Teleport_Only): Спуститься под землю
    // if (settings.movementSettings.navigationType == MovementSettings::NavigationType::Teleport_Only)
    // {
    //     children.push_back(std::make_unique<MoveToOffsetAction>(Vector3{0, 0, -100.0f}));
    // }

    return std::make_unique<SequenceNode>(std::move(children));
}