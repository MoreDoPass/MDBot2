// Файл: src/core/Bot/CombatLogic/Paladin/Common/PaladinCommon.cpp

#include "PaladinCommon.h"

#include "PaladinSpells.h"
#include "core/Bot/CombatLogic/Common/CombatUtils.h"

// Подключаем все "кирпичики", которые нам нужны для строительства этой ветки.
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/SequenceNode.h"
#include "core/Bot/Behaviors/Combat/IsLevelCondition.h"
#include "core/Bot/Behaviors/Combat/HasBuffCondition.h"
#include "core/Bot/Behaviors/Combat/IsSpellOnCooldownCondition.h"
#include "core/Bot/Behaviors/Combat/CastSpellAction.h"
#include "core/Bot/Behaviors/Conditions/IsHealthCondition.h"
#include "core/Bot/Behaviors/Utility/FailNode.h"
#include "core/BehaviorTree/BTContext.h"  // Нужен для работы узлов

std::unique_ptr<BTNode> PaladinCommon::buildDefaultSealLogic(BTContext& context)
{
    // --- ВЕТКА 1: Логика для уровня 20+ ---
    // "ЕСЛИ (уровень >= 20) И (на мне НЕТ Печати повиновения) И (она НЕ на кд), ТОГДА (использовать ее)"
    auto sequenceForLevel20 = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;
        children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 20));
        children.push_back(std::make_unique<HasBuffCondition>(UnitSource::Self, PaladinSpells::SEAL_OF_COMMAND, false));
        children.push_back(std::make_unique<IsSpellOnCooldownCondition>(PaladinSpells::SEAL_OF_COMMAND));
        children.push_back(std::make_unique<CastSpellAction>(UnitSource::Self, PaladinSpells::SEAL_OF_COMMAND));
        return std::make_unique<SequenceNode>(std::move(children));
    }();

    // --- ВЕТКА 2: Логика для уровня 1-19 ---
    // "ЕСЛИ (уровень < 20) И (на мне НЕТ Печати праведности), ТОГДА (использовать ее)"
    auto sequenceForLevel1 = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;
        children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::Less, 20));
        children.push_back(
            std::make_unique<HasBuffCondition>(UnitSource::Self, PaladinSpells::SEAL_OF_RIGHTEOUSNESS, false));
        children.push_back(std::make_unique<CastSpellAction>(UnitSource::Self, PaladinSpells::SEAL_OF_RIGHTEOUSNESS));
        return std::make_unique<SequenceNode>(std::move(children));
    }();

    // Собираем обе ветки в один узел-переключатель "ИЛИ".
    // Он сначала попробует выполнить логику для 20+, если она провалится (например, мы 10 уровня),
    // он попробует выполнить логику для 1-19.
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(std::move(sequenceForLevel20));
    rootChildren.push_back(std::move(sequenceForLevel1));

    return std::make_unique<SelectorNode>(std::move(rootChildren));
}

std::unique_ptr<BTNode> PaladinCommon::buildJudgementLogic(BTContext& context)
{
    // Для использования скилла ВСЕ условия должны быть выполнены.
    // Поэтому мы используем SequenceNode ("И... И... И... ТОГДА...")
    std::vector<std::unique_ptr<BTNode>> children;

    // Условие 1: Мы достигли 4-го уровня?
    children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 4));

    // Условие 2: На нас есть любая из печатей? (Пока для простоты проверим одну)
    // ВАЖНО: Id печати 20375 (Seal of Command) используется как пример.
    // У Правосудия нет своего баффа, оно "сжигает" активную печать.
    // Поэтому мы проверяем, что печать на нас ЕСТЬ.
    children.push_back(std::make_unique<HasBuffCondition>(UnitSource::Self, PaladinSpells::SEAL_OF_COMMAND, true));

    // Условие 3: Скилл не на кулдауне? (ID Правосудия - 20271 для примера)
    constexpr int JUDGEMENT_SPELL_ID = 20271;
    children.push_back(std::make_unique<IsSpellOnCooldownCondition>(JUDGEMENT_SPELL_ID));

    // Условие 4: Мы в радиусе 10 ярдов? (Для этого вам нужно будет создать новый узел IsTargetInRangeCondition)
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(10.0f)); // <-- ПОКА ЗАКОММЕНТИРОВАНО

    // Действие: Если все проверки выше прошли, кастуем!
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, JUDGEMENT_SPELL_ID));

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> PaladinCommon::buildHammerOfWrathLogic(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId =
        CombatUtils::findHighestAvailableRankId(context.character->getLevel(), PaladinSpells::HAMMER_OF_WRATH_RANKS);

    // 2. Если калькулятор вернул 0, значит мы еще не доросли до этого скилла.
    //    Нет смысла строить ветку, просто возвращаем пустоту.
    if (bestRankId == 0)
    {
        return std::make_unique<FailNode>();
    }

    // 3. Собираем саму ветку (SequenceNode), т.к. ВСЕ условия должны быть выполнены.
    std::vector<std::unique_ptr<BTNode>> children;

    // Условие 1: Здоровье цели меньше 20%?
    children.push_back(std::make_unique<IsHealthCondition>(UnitSource::CurrentTarget, ComparisonType::Less,
                                                           HealthCheckType::Percentage,  // <--- ВОТ ИСПРАВЛЕНИЕ
                                                           20.0f));

    // Условие 2: Цель в радиусе 30 ярдов?
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(30.0f));

    // Условие 3: Скилл НЕ на кулдауне?
    // Используем ID лучшего ранга, который мы нашли. Это абсолютно корректно.
    children.push_back(std::make_unique<IsSpellOnCooldownCondition>(bestRankId));

    // Условие 4: Хватает ли маны?
    // children.push_back(std::make_unique<HasEnoughManaCondition>(bestRankId));

    // Действие: Если все проверки прошли, кастуем!
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, bestRankId));

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> PaladinCommon::buildSelfBlessingLogic(BTContext& context,
                                                              const std::vector<SpellRankInfo>& ranks)
{
    int bestRankId = CombatUtils::findHighestAvailableRankId(context.character->getLevel(), ranks);
    if (bestRankId == 0)
    {
        return std::make_unique<FailNode>();
    }

    std::vector<std::unique_ptr<BTNode>> children;
    children.push_back(std::make_unique<HasBuffCondition>(UnitSource::Self, bestRankId, false));
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::Self, bestRankId));
    return std::make_unique<SequenceNode>(std::move(children));
}