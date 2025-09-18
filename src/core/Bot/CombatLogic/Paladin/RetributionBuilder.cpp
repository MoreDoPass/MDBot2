#include "RetributionBuilder.h"
#include <vector>  // Убедись, что vector подключен

// Включаем стандартные узлы
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/SequenceNode.h"

// Включаем наши "кирпичики"
#include "core/Bot/Behaviors/Combat/IsLevelCondition.h"
#include "core/Bot/Behaviors/Combat/HasBuffCondition.h"
#include "core/Bot/Behaviors/Combat/CastSpellAction.h"

namespace PaladinSpells
{
constexpr int SEAL_OF_RIGHTEOUSNESS = 21084;
constexpr int SEAL_OF_COMMAND = 20375;
}  // namespace PaladinSpells

// --- Логика ВНЕ боя ---
std::unique_ptr<BTNode> RetributionBuilder::buildOutOfCombatLogic(BTContext& context)
{
    // --- ВЕТКА 1: Логика для уровня 20+ ---
    auto sequenceForLevel20 = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;
        children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 20));
        children.push_back(std::make_unique<HasBuffCondition>(UnitSource::Self, PaladinSpells::SEAL_OF_COMMAND, false));
        children.push_back(std::make_unique<CastSpellAction>(UnitSource::Self, PaladinSpells::SEAL_OF_COMMAND));
        return std::make_unique<SequenceNode>(std::move(children));
    }();  // <-- скобки () сразу вызывают лямбда-функцию

    // --- ВЕТКА 2: Логика для уровня 1-19 ---
    auto sequenceForLevel1 = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;
        children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::Less, 20));
        children.push_back(
            std::make_unique<HasBuffCondition>(UnitSource::Self, PaladinSpells::SEAL_OF_RIGHTEOUSNESS, false));
        children.push_back(std::make_unique<CastSpellAction>(UnitSource::Self, PaladinSpells::SEAL_OF_RIGHTEOUSNESS));
        return std::make_unique<SequenceNode>(std::move(children));
    }();

    // --- Собираем главный Selector ---
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(std::move(sequenceForLevel20));
    rootChildren.push_back(std::move(sequenceForLevel1));

    return std::make_unique<SelectorNode>(std::move(rootChildren));
}

// --- Логика ВНУТРИ боя (ПОКА НЕ РЕАЛИЗОВАНА) ---
std::unique_ptr<BTNode> RetributionBuilder::buildInCombatLogic(BTContext& context)
{
    return nullptr;
}

// --- Главный сборщик ---
std::unique_ptr<BTNode> RetributionBuilder::buildCombatTree(BTContext& context)
{
    return buildOutOfCombatLogic(context);
}