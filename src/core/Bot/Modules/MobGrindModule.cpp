// --- НАЧАЛО ФАЙЛА MobGrindModule.cpp ---

#include "MobGrindModule.h"

#include <vector>
#include <QLoggingCategory>

// --- Framework ---
#include "core/BehaviorTree/SequenceNode.h"
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/InverterNode.h"
#include "core/BehaviorTree/WhileSuccessDecorator.h"

// --- Conditions ---
#include "core/Bot/Behaviors/Targeting/HasTargetCondition.h"
#include "core/Bot/Behaviors/Combat/IsInCombatCondition.h"
#include "core/Bot/Behaviors/Conditions/IsHealthCondition.h"
#include "core/Bot/Behaviors/Conditions/IsInRangeCondition.h"
#include "core/Bot/Behaviors/Conditions/IsPlayersNearbyCondition.h"

// --- Targeting ---
#include "core/Bot/Behaviors/Targeting/ClearTargetAction.h"
// *** НУЖНО СОЗДАТЬ ***
#include "core/Bot/Behaviors/Targeting/FindObjectByIdAction.h"
// #include "core/Bot/Behaviors/Targeting/FindLootableCorpseAction.h"

// --- Movement ---
#include "core/Bot/Behaviors/Movement/FaceTargetAction.h"
#include "core/Bot/Behaviors/Movement/FollowPathAction.h"
#include "core/Bot/Behaviors/Movement/MoveToTargetAction.h"
#include "core/Bot/Behaviors/Movement/TeleportToTargetAction.h"

// --- Combat ---
#include "core/Bot/Behaviors/Combat/CastSpellAction.h"

// --- Interaction ---
#include "core/Bot/Behaviors/Interactions/InteractWithTargetAction.h"
// *** НУЖНО СОЗДАТЬ ***
// #include "core/Bot/Behaviors/Interactions/UseItemAction.h"

// --- Profile ---
// *** НУЖНО СОЗДАТЬ ***
#include "core/Bot/Behaviors/Profiles/LoadGrindingProfileAction.h"

// --- Utility ---
#include "core/Bot/Behaviors/Utility/WaitAction.h"

// Определяем категорию логирования
Q_LOGGING_CATEGORY(lcMobGrindModule, "core.bot.modules.mob_grind")

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

std::unique_ptr<BTNode> MobGrindModule::createPanicBranch(BTContext& context)
{
    auto children = std::vector<std::unique_ptr<BTNode>>();
    // Шаг 1: Проверить, есть ли рядом игроки в радиусе 30 метров.
    children.push_back(std::make_unique<IsPlayersNearbyCondition>());
    // Шаг 2: Если есть, просто следовать по маршруту, чтобы убежать.
    children.push_back(createFollowPathBranch(context));
    qCDebug(lcMobGrindModule) << "Panic branch created: Flee if players are nearby.";
    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> MobGrindModule::createRestBranch(BTContext& context)
{
    auto selectorChildren = std::vector<std::unique_ptr<BTNode>>();

    // --- Вариант 1: Восстановить здоровье едой ---
    {
        auto sequence = std::vector<std::unique_ptr<BTNode>>();
        // Условие 1: Мы не должны быть в бою.
        sequence.push_back(std::make_unique<InverterNode>(std::make_unique<IsInCombatCondition>(UnitSource::Self)));
        // Условие 2: Наше здоровье ниже 50%.
        sequence.push_back(std::make_unique<IsHealthCondition>(UnitSource::Self, ComparisonType::Less,
                                                               HealthCheckType::Percentage, 50.0f));
        // Действие 1: Использовать еду.
        // *** НУЖНО СОЗДАТЬ УЗЕЛ UseItemAction(itemId) ***
        // sequence.push_back(std::make_unique<UseItemAction>(context.settings.grindingSettings.foodItemId));

        // Действие 2: Ждать, пока здоровье не станет >= 95%.
        sequence.push_back(std::make_unique<WhileSuccessDecorator>(std::make_unique<IsHealthCondition>(
            UnitSource::Self, ComparisonType::Less, HealthCheckType::Percentage, 95.0f)));
        selectorChildren.push_back(std::make_unique<SequenceNode>(std::move(sequence)));
    }

    // --- Вариант 2: Восстановить ману (логика аналогична) ---
    // { ... }

    qCDebug(lcMobGrindModule) << "Rest branch created: Eat/drink if health/mana is low and not in combat.";
    // Selector выберет первое необходимое действие: поесть ИЛИ попить.
    return std::make_unique<SelectorNode>(std::move(selectorChildren));
}

std::unique_ptr<BTNode> MobGrindModule::createLootBranch(BTContext& context)
{
    auto children = std::vector<std::unique_ptr<BTNode>>();

    // Шаг 1: Найти ближайший труп, который можно обыскать.
    // *** НУЖНО СОЗДАТЬ УЗЕЛ FindLootableCorpseAction() ***
    // children.push_back(std::make_unique<FindLootableCorpseAction>());

    // Шаг 2: Подойти вплотную (4 метра).
    // ИЗМЕНЕНО: Используем универсальный узел движения
    children.push_back(createMovementNode(context));
    children.push_back(std::make_unique<IsInRangeCondition>(4.0f));

    // Шаг 3: Взаимодействовать (залутать).
    children.push_back(std::make_unique<InteractWithTargetAction>());

    // Шаг 4: Подождать 1.5 секунды для обработки лута.
    children.push_back(std::make_unique<WaitAction>(1500.0f));

    // Шаг 5: Очистить цель, чтобы не пытаться лутать ее снова.
    children.push_back(std::make_unique<ClearTargetAction>());

    qCDebug(lcMobGrindModule) << "Loot branch created: Find, move to, and loot corpses.";
    // Sequence, т.к. все шаги должны выполниться последовательно.
    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> MobGrindModule::createFullGrindCycleBranch(BTContext& context)
{
    auto children = std::vector<std::unique_ptr<BTNode>>();

    // Шаг 1: Найти живого NPC из списка, который хранится в настройках.
    // Мы передаем 'true', чтобы искать ТОЛЬКО живых мобов.
    children.push_back(std::make_unique<FindObjectByIdAction>(context.settings.grindingSettings.npcIdsToGrind));

    // Шаг 2: Повернуться к цели.
    children.push_back(std::make_unique<FaceTargetAction>());

    // Шаг 3: Подойти на дистанцию атаки.
    // ИЗМЕНЕНО: Используем универсальный узел движения
    children.push_back(createMovementNode(context));

    // Шаг 4: Инициировать бой (Пулл).
    // ...

    qCDebug(lcMobGrindModule) << "Grind cycle branch created: Find and move to a new target.";
    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> MobGrindModule::createFollowPathBranch(BTContext& context)
{
    auto children = std::vector<std::unique_ptr<BTNode>>();

    // Шаг 1: Выбрать следующую точку маршрута.
    children.push_back(std::make_unique<FollowPathAction>());

    // Шаг 2: Двигаться к этой точке.
    // ИЗМЕНЕНО: Используем универсальный узел движения
    children.push_back(createMovementNode(context));

    qCDebug(lcMobGrindModule) << "Follow path branch created.";
    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> MobGrindModule::createWorkLogicBranch(BTContext& context,
                                                              std::unique_ptr<BTNode> combatBehavior)
{
    auto children = std::vector<std::unique_ptr<BTNode>>();

    // --- Приоритет 1: Бой ---
    {
        auto combatSequence = std::vector<std::unique_ptr<BTNode>>();

        // --- ИСПРАВЛЕНИЕ ЗДЕСЬ ---
        // Мы не можем использовать фигурные скобки {} для инициализации вектора с unique_ptr.
        // Вместо этого мы создаем вектор и наполняем его вручную.
        {
            // 1. Создаем пустой вектор для дочерних узлов условия.
            auto conditionChildren = std::vector<std::unique_ptr<BTNode>>();
            // 2. Добавляем в него узлы. push_back для временных объектов (r-value) автоматически использует move.
            conditionChildren.push_back(std::make_unique<HasTargetCondition>(GameObjectType::Unit));
            conditionChildren.push_back(std::make_unique<IsInCombatCondition>(UnitSource::Self));

            // 3. Создаем родительский узел SelectorNode, ПЕРЕМЕЩАЯ в него готовый вектор.
            auto combatCondition = std::make_unique<SelectorNode>(std::move(conditionChildren));

            // Теперь мы можем безопасно добавить готовый узел в нашу последовательность.
            combatSequence.push_back(std::move(combatCondition));
        }

        // Перемещаем combatBehavior, как и в прошлый раз.
        combatSequence.push_back(std::move(combatBehavior));
        children.push_back(std::make_unique<SequenceNode>(std::move(combatSequence)));
    }

    // --- Приоритет 2: Поиск новой цели, если не в бою ---
    children.push_back(createFullGrindCycleBranch(context));

    // --- Приоритет 3: Если целей нет, просто идти по маршруту ---
    children.push_back(createFollowPathBranch(context));

    qCDebug(lcMobGrindModule) << "Work logic branch created: Combat > Find Target > Follow Path.";
    return std::make_unique<SelectorNode>(std::move(children));
}

std::unique_ptr<BTNode> MobGrindModule::build(BTContext& context, std::unique_ptr<BTNode> combatBehavior)
{
    qCDebug(lcMobGrindModule) << "Building MobGrindModule behavior tree...";
    auto rootChildren = std::vector<std::unique_ptr<BTNode>>();

    // --- Шаг 1: Загрузить профиль гринда ---
    // Этот узел должен быть первым. Он заполнит context.grindingProfile и перезапишет
    // ID мобов, если они указаны в файле.
    rootChildren.push_back(std::make_unique<LoadGrindingProfileAction>());

    // --- Шаг 2: Основной цикл принятия решений (Selector) ---
    {
        auto mainSelectorChildren = std::vector<std::unique_ptr<BTNode>>();

        // Приоритет 1 (высший): Убежать от игроков.
        mainSelectorChildren.push_back(createPanicBranch(context));

        // Приоритет 2: Восстановить здоровье/ману. (ПОКА НЕ РЕАЛИЗОВАНО)
        // mainSelectorChildren.push_back(createRestBranch(context));

        // Приоритет 3: Собрать добычу. (ПОКА НЕ РЕАЛИЗОВАНО)
        // mainSelectorChildren.push_back(createLootBranch(context));

        // Приоритет 4 (низший): Основная работа - бой, поиск целей и движение.
        mainSelectorChildren.push_back(createWorkLogicBranch(context, std::move(combatBehavior)));

        rootChildren.push_back(std::make_unique<SelectorNode>(std::move(mainSelectorChildren)));
    }

    qCDebug(lcMobGrindModule) << "MobGrindModule behavior tree built successfully.";
    // Корень - это Sequence: сначала загружаем профиль, потом запускаем основной цикл.
    return std::make_unique<SequenceNode>(std::move(rootChildren));
}
// --- КОНЕЦ ФАЙЛА MobGrindModule.cpp ---