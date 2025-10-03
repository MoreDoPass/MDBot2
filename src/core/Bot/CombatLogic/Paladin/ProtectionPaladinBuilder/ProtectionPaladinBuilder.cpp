#include "ProtectionPaladinBuilder.h"
#include <vector>  // Убедись, что vector подключен

// Включаем стандартные узлы
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/SequenceNode.h"

#include "core/Bot/CombatLogic/Common/CombatCommon.h"
#include "core/Bot/CombatLogic/Common/CombatUtils.h"
#include "core/Bot/CombatLogic/Paladin/Common/PaladinCommon.h"
#include "core/Bot/CombatLogic/Paladin/Common/PaladinSpells.h"

// Включаем наши "кирпичики"
#include "core/Bot/Behaviors/Combat/IsLevelCondition.h"
#include "core/Bot/Behaviors/Combat/HasBuffCondition.h"
#include "core/Bot/Behaviors/Combat/CastSpellAction.h"
#include "core/Bot/Behaviors/Combat/IsInCombatCondition.h"
#include "core/Bot/Behaviors/Combat/FindAggressorAction.h"
#include "core/Bot/Behaviors/Combat/IsSpellOnCooldownCondition.h"
#include "core/Bot/Behaviors/Conditions/IsFacingTargetCondition.h"
#include "core/Bot/Behaviors/Movement/FaceTargetAction.h"
#include "core/Bot/Behaviors/Movement/TeleportToTargetAction.h"  // Убедитесь, что он подключен
#include "core/Bot/Behaviors/Combat/StartAutoAttackAction.h"
#include "core/Bot/Behaviors/Combat/IsAutoAttackingCondition.h"
#include "core/Bot/Behaviors/Conditions/IsHealthCondition.h"

// --- БАЗА ДАННЫХ: Ранги уникальных заклинаний Прото-Паладина ---

const std::vector<SpellRankInfo> BLESSING_OF_KINGS_RANKS = {
    // ЗАПОЛНИТЬ ПОЗЖЕ
    {20217, 20}  // Ранг 1 (для примера)
};

const std::vector<SpellRankInfo> HOLY_SHIELD_RANKS = {
    // Как ты и просил, оставляем только самый сильный ранг для каждого уровня
    {48952, 80},  // Ранг 6
    {48951, 75},  // Ранг 5
    {27179, 70},  // Ранг 4
    {20928, 60},  // Ранг 3
    {20927, 51}   // Ранг 2 (Ранг 1 на том же уровне пропускаем)
};

const std::vector<SpellRankInfo> AVENGERS_SHIELD_RANKS = {
    {48827, 80},  // Ранг 5
    {48826, 75},  // Ранг 4
    {32700, 70},  // Ранг 3
    {32699, 61}   // Ранг 2 (Ранг 1 на том же уровне пропускаем)
};

const std::vector<SpellRankInfo> SHIELD_OF_RIGHTEOUSNESS_RANKS = {
    {61411, 80},  // Ранг 2 (так в твоем списке)
    {53600, 75}   // Ранг 2 (так в твоем списке)
};

static std::unique_ptr<BTNode> buildBlessingOfSanctuaryBranch()
{
    std::vector<std::unique_ptr<BTNode>> children;
    constexpr int BLESSING_OF_SANCTUARY_ID = 20911;

    // TODO: Добавить логику (проверка уровня, отсутствия баффа и т.д.)

    // Заглушка, чтобы функция что-то возвращала
    return std::make_unique<SequenceNode>(std::move(children));
}

// 2) Щит небес (Holy Shield)
static std::unique_ptr<BTNode> buildHolyShieldBranch(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;

    // TODO: Добавить логику (вычисление ранга, проверка кулдауна и т.д.)

    // Заглушка, чтобы функция что-то возвращала
    return std::make_unique<SequenceNode>(std::move(children));
}

// 3) Щит мстителя (Avenger's Shield)
static std::unique_ptr<BTNode> buildAvengersShieldBranch(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;

    // TODO: Добавить логику (вычисление ранга, проверка кулдауна и т.д.)

    return std::make_unique<SequenceNode>(std::move(children));
}

// 4) Молот праведника (Hammer of the Righteous)
static std::unique_ptr<BTNode> buildHammerOfTheRighteousBranch()
{
    // Используем SequenceNode ("И"), т.к. все условия должны быть выполнены.
    std::vector<std::unique_ptr<BTNode>> children;

    // ID заклинания
    constexpr int HAMMER_OF_THE_RIGHTEOUS_ID = 53595;

    // --- Условия ---

    // Условие 1: Мы достигли 71-го уровня?
    children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 71));

    // Условие 2: Заклинание не на кулдауне?
    children.push_back(std::make_unique<IsSpellOnCooldownCondition>(HAMMER_OF_THE_RIGHTEOUS_ID));

    // --- Что можно добавить потом? ---
    // Условие 3: Цель в радиусе удара?
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(4.0f));

    // Условие 4: Хватает ли маны?
    // children.push_back(std::make_unique<HasEnoughManaCondition>(HAMMER_OF_THE_RIGHTEOUS_ID));

    // --- Действие ---

    // Если все проверки выше прошли, используем заклинание.
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, HAMMER_OF_THE_RIGHTEOUS_ID));

    return std::make_unique<SequenceNode>(std::move(children));
}

// 5) Щит праведности (Shield of Righteousness)
static std::unique_ptr<BTNode> buildShieldOfRighteousnessBranch(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;

    // TODO: Добавить логику (вычисление ранга, проверка кулдауна и т.д.)

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> ProtectionPaladinBuilder::buildOutOfCombatLogic(BTContext& context)
{
    // Создаем список для веток нашего дерева ("ИЛИ ... ИЛИ ...")
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(PaladinCommon::buildDefaultSealLogic(context));

    rootChildren.push_back(PaladinCommon::buildSelfBlessingLogic(context, PaladinSpells::BLESSING_OF_KINGS_RANKS));

    // --- ШАГ 3: Возвращаем собранное дерево ---
    // SelectorNode будет пытаться выполнить каждую ветку по очереди:
    // сначала попробует баффнуть печать, потом попробует баффнуть благословение.
    return std::make_unique<SelectorNode>(std::move(rootChildren));
}

std::unique_ptr<BTNode> ProtectionPaladinBuilder::buildInCombatLogic(BTContext& context)
{
    // --- Ветка 2: Боевая ротация ---
    std::vector<std::unique_ptr<BTNode>> rotationChildren;

    rotationChildren.push_back(PaladinCommon::buildJudgementLogic(context));
    rotationChildren.push_back(PaladinCommon::buildHammerOfWrathLogic(context));

    // Добавляем логику автоатаки как действие с самым низким приоритетом.
    rotationChildren.push_back(CombatCommon::buildEnsureAutoAttackLogic(context));

    auto combatRotationSelector = std::make_unique<SelectorNode>(std::move(rotationChildren));

    // --- Главный узел для боевой логики ---
    // Собираем финальное дерево для боя: "Сначала подготовься, А ПОТОМ используй ротацию"
    std::vector<std::unique_ptr<BTNode>> rootChildren;

    // [ ИЗМЕНЕНИЕ ]
    // Вместо громоздкого лямбда-выражения мы просто вызываем нашу новую общую функцию.
    // Она вернет уже готовую ветку для сближения с целью.
    rootChildren.push_back(CombatCommon::buildDefaultEngageLogic(context));

    // Добавляем нашу уникальную ротацию следом.
    rootChildren.push_back(std::move(combatRotationSelector));

    // Возвращаем всю боевую логику как одну большую последовательность.
    return std::make_unique<SequenceNode>(std::move(rootChildren));
}

// --- Главный сборщик ---
std::unique_ptr<BTNode> ProtectionPaladinBuilder::buildCombatTree(BTContext& context)
{
    // --- Ветка 1: Логика для состояния "В БОЮ" ---
    auto sequenceInCombat = [&]() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;
        // Условие: "Я должен быть в бою"
        children.push_back(std::make_unique<IsInCombatCondition>(UnitSource::Self, true));
        // Действия: вся наша боевая логика (пока только поиск агрессора)
        children.push_back(buildInCombatLogic(context));
        return std::make_unique<SequenceNode>(std::move(children));
    }();  // <-- скобки () сразу вызывают лямбда-функцию

    // --- Ветка 2: Логика для состояния "ВНЕ БОЯ" ---
    auto sequenceOutOfCombat = [&]() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;
        // Условие: "Я НЕ должен быть в бою"
        children.push_back(std::make_unique<IsInCombatCondition>(UnitSource::Self, false));
        // Действия: баффы, сбор руды и т.д.
        children.push_back(buildOutOfCombatLogic(context));
        return std::make_unique<SequenceNode>(std::move(children));
    }();

    // --- Корень дерева: Selector ---
    // Selector - это "или... или...". Он попытается выполнить первую ветку.
    // Если ее условие (IsInCombat == true) провалится, он перейдет ко второй.
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(std::move(sequenceInCombat));
    rootChildren.push_back(std::move(sequenceOutOfCombat));

    return std::make_unique<SelectorNode>(std::move(rootChildren));
}