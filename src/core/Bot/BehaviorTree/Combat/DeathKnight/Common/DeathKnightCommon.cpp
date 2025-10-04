// Файл: src/core/Bot/CombatLogic/DeathKnight/Common/DeathKnightCommon.cpp

#include "DeathKnightCommon.h"
#include "DeathKnightSpells.h"
#include "core/Bot/BehaviorTree/Combat/Common/CombatUtils.h"

// Подключаем необходимые узлы
#include "core/BehaviorTree/SequenceNode.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/HasBuffCondition.h"
// #include "core/Bot/BehaviorTree/Nodes/Combat/IsSpellOnCooldownCondition.h" // Удалено по договоренности
#include "core/Bot/BehaviorTree/Nodes/Combat/CastSpellAction.h"
#include "core/Bot/BehaviorTree/Nodes/Class/DeathKnight/HasRunesCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/IsLevelCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Utility/FailNode.h"
// Включаем логирование
#include <QLoggingCategory>

std::unique_ptr<BTNode> DeathKnightCommon::buildIcyTouchLogic(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId =
        CombatUtils::findHighestAvailableRankId(context.character->getLevel(), DeathKnightSpells::ICY_TOUCH_RANKS);

    // 2. Если калькулятор вернул 0, значит, скилл недоступен.
    if (bestRankId == 0)
    {
        return std::make_unique<FailNode>();
    }

    // SequenceNode: все условия должны быть выполнены для каста.
    std::vector<std::unique_ptr<BTNode>> children;

    // Условие 1: На цели НЕТ дебаффа Озноб (Frost Fever).
    // Используем HasBuffCondition с mustBePresent = false.
    children.push_back(std::make_unique<HasBuffCondition>(UnitSource::CurrentTarget,
                                                          DeathKnightSpells::FROST_FEVER_DEBUFF_ID,
                                                          false  // Success только если ауры НЕТ
                                                          ));

    // Условие 2: Цель в радиусе (нужно будет добавить)
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(30.0f));

    // Условие 3: Проверка на руны / ресурсы (будет добавлено позже)

    // Действие: Кастуем Ледяное Прикосновение нужного ранга.
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, bestRankId));

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> DeathKnightCommon::buildPlagueStrikeLogic(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId =
        CombatUtils::findHighestAvailableRankId(context.character->getLevel(), DeathKnightSpells::PLAGUE_STRIKE_RANKS);

    // 2. Если калькулятор вернул 0, значит, скилл недоступен.
    if (bestRankId == 0)
    {
        return std::make_unique<FailNode>();
    }

    // SequenceNode: все условия должны быть выполнены для каста.
    std::vector<std::unique_ptr<BTNode>> children;

    // Условие 1: На цели НЕТ дебаффа Кровавая Чума (Blood Plague).
    // Используем HasBuffCondition с mustBePresent = false.
    children.push_back(std::make_unique<HasBuffCondition>(UnitSource::CurrentTarget,
                                                          DeathKnightSpells::BLOOD_PLAGUE_DEBUFF_ID,
                                                          false  // Success только если ауры НЕТ
                                                          ));

    // Условие 2: Цель в радиусе (Удар Чумы - ближний бой, 5 ярдов)
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(5.0f));

    // Условие 3: Проверка на руны / ресурсы (будет добавлено позже)

    // Действие: Кастуем Удар Чумы нужного ранга.
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, bestRankId));

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> DeathKnightCommon::buildDeathStrikeLogic(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId =
        CombatUtils::findHighestAvailableRankId(context.character->getLevel(), DeathKnightSpells::DEATH_STRIKE_RANKS);

    // 2. Если калькулятор вернул 0, значит, скилл недоступен.
    if (bestRankId == 0)
    {
        return std::make_unique<FailNode>();
    }

    // SequenceNode: все условия должны быть выполнены для каста.
    std::vector<std::unique_ptr<BTNode>> children;

    // Условие 1: Проверка наличия необходимых рун.
    // Удар Смерти требует 1 руну Льда И 1 руну Нечестивости.
    children.push_back(std::make_unique<HasRunesCondition>(RuneType::Frost, 1));
    children.push_back(std::make_unique<HasRunesCondition>(RuneType::Unholy, 1));

    // Условие 1: Цель в радиусе (Удар Смерти - ближний бой, 5 ярдов)
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(5.0f));

    // Условие 2: Скилл НЕ на кулдауне (на всякий случай, если есть глобальный КД или талант).
    // children.push_back(
    //     std::make_unique<IsSpellOnCooldownCondition>(bestRankId));

    // Условие 3: Проверка на руны / ресурсы (будет добавлено позже, это ключевое условие)

    // Действие: Кастуем Удар Смерти нужного ранга.
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, bestRankId));

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> DeathKnightCommon::buildHornOfWinterLogic(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId =
        CombatUtils::findHighestAvailableRankId(context.character->getLevel(), DeathKnightSpells::HORN_OF_WINTER_RANKS);

    // 2. Если ранг не найден, завершаем ветку.
    if (bestRankId == 0)
    {
        return std::make_unique<FailNode>();
    }

    // SequenceNode: все условия должны быть выполнены для каста.
    std::vector<std::unique_ptr<BTNode>> children;

    // Условие 1: На себе НЕТ баффа Зимний Горн.
    // Проверяем по ID ауры (57623), а не по ID ранга, т.к. аура одна.
    children.push_back(std::make_unique<HasBuffCondition>(UnitSource::Self, bestRankId,
                                                          false  // Success только если ауры НЕТ
                                                          ));

    // Действие: Кастуем Зимний Горн нужного ранга (кастуется на себя, UnitSource::Self).
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::Self, bestRankId));

    return std::make_unique<SequenceNode>(std::move(children));
}