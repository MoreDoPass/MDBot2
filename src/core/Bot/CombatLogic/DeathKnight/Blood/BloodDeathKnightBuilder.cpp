#include "BloodDeathKnightBuilder.h"
#include <vector>  // Убедись, что vector подключен

// Включаем стандартные узлы
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/SequenceNode.h"
#include "core/BehaviorTree/RunWhileConditionDecorator.h"
#include "core/Bot/Behaviors/Utility/FailNode.h"

#include "core/Bot/CombatLogic/Common/CombatCommon.h"
#include "core/Bot/CombatLogic/Common/CombatUtils.h"
#include "core/Bot/CombatLogic/DeathKnight/Common/DeathKnightSpells.h"  // <-- НУЖНО
#include "core/Bot/CombatLogic/DeathKnight/Common/DeathKnightCommon.h"  // <-- НУЖНО

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
#include "core/Bot/Behaviors/Class/DeathKnight/HasRunesCondition.h"
#include "core/Bot/Behaviors/Conditions/HasEnoughPowerCondition.h"

#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(logBloodDKBuilder)
Q_LOGGING_CATEGORY(logBloodDKBuilder, "dk.blood.builder", QtWarningMsg)

// --- БАЗА ДАННЫХ: Ранги уникальных заклинаний Прото-Паладина ---

// Удар в сердце
// Примечание: Уровень 59 был повышен до 60 для контроля логики ротации.
inline const std::vector<SpellRankInfo> HEART_STRIKE_RANKS = {
    {55262, 80},  // Ранг 6: Heart Strike
    {55261, 74},  // Ранг 5: Heart Strike
    {55260, 69},  // Ранг 4: Heart Strike
    {55259, 64},  // Ранг 3: Heart Strike
    {55258, 60}   // Ранг 2: Heart Strike (Скорректирован с 59 до 60 для логики)
};

std::unique_ptr<BTNode> BloodDeathKnightBuilder::buildHeartStrikeBranch(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId =
        CombatUtils::findHighestAvailableRankId(context.character->getLevel(), DeathKnightSpells::HEART_STRIKE_RANKS);

    // 2. Если ранг не найден (т.е. уровень < 60, как мы установили), завершаем ветку.
    if (bestRankId == 0)
    {
        return std::make_unique<FailNode>();
    }

    // SequenceNode: все условия должны быть выполнены для каста.
    std::vector<std::unique_ptr<BTNode>> children;
    children.push_back(std::make_unique<HasRunesCondition>(RuneType::Blood, 1));
    // Условие 1: Цель в радиусе (Удар в Сердце - ближний бой, 5 ярдов)
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(5.0f));

    // Условие 2: Проверка на руны / ресурсы (будет добавлено позже, это ключевое условие)

    // Действие: Кастуем Удар в Сердце нужного ранга.
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, bestRankId));

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> BloodDeathKnightBuilder::buildReapBranch(BTContext& context)
{
    // Так как нет рангов, просто используем константный ID.
    constexpr int REAP_SPELL_ID = DeathKnightSpells::REAP_SPELL_ID;

    // SequenceNode: все условия должны быть выполнены для каста.
    std::vector<std::unique_ptr<BTNode>> children;

    // Условие 1: Мы достигли 60-го уровня? (По требованию, т.к. нет рангов)
    children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 60));

    children.push_back(std::make_unique<HasEnoughPowerCondition>(PowerType::RunicPower, 32));

    // Действие: Кастуем Пожинание.
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, REAP_SPELL_ID));

    return std::make_unique<SequenceNode>(std::move(children));
}

std::unique_ptr<BTNode> BloodDeathKnightBuilder::buildOutOfCombatLogic(BTContext& context)
{
    // Создаем список для веток нашего дерева ("ИЛИ ... ИЛИ ...")
    // SelectorNode будет пытаться выполнить каждую ветку по очереди до первой успешной (или Running).
    std::vector<std::unique_ptr<BTNode>> rootChildren;

    // 1. [ВЫСШИЙ ПРИОРИТЕТ] Поддержание Зимнего Горна.
    // Если Горн уже есть, эта ветка вернет Failure, и Selector перейдет дальше.
    // Если Горна нет, ветка его кастует и вернет Running/Success, и Selector остановится.
    rootChildren.push_back(DeathKnightCommon::buildHornOfWinterLogic(context));

    // TODO: Здесь будут другие баффы/подготовки, общие для всех ДК.
    // Например: бафф на оружие (Runeforging).

    // Возвращаем собранное дерево
    return std::make_unique<SelectorNode>(std::move(rootChildren));
}

std::unique_ptr<BTNode> BloodDeathKnightBuilder::buildInCombatLogic(BTContext& context)
{
    // --- Ветка 2: Боевая ротация ---
    // SelectorNode: выбирает ОДНО действие из списка.
    std::vector<std::unique_ptr<BTNode>> rotationChildren;

    // 1. [ВЫСШИЙ ПРИОРИТЕТ] Поддержание болезней.
    // Если на цели нет Озноба, эта ветка кастует ЛП и останавливает Selector.
    rotationChildren.push_back(DeathKnightCommon::buildIcyTouchLogic(context));
    // Если Озноб есть (Failure), Selector переходит сюда. Если нет КЧ, эта ветка кастует УЧ.
    rotationChildren.push_back(DeathKnightCommon::buildPlagueStrikeLogic(context));

    // 2. [ВЫСОКИЙ/СРЕДНИЙ ПРИОРИТЕТ] Специфические скиллы (до основного спамма)
    // Удар в Сердце - основной расходчик.
    rotationChildren.push_back(DeathKnightCommon::buildDeathStrikeLogic(context));
    rotationChildren.push_back(buildHeartStrikeBranch(context));
    // 3. [СРЕДНИЙ/НИЗКИЙ ПРИОРИТЕТ] Общие скиллы (если нет ресурсов на Heart Strike)
    // Удар Смерти - всегда важен для танка, но после болезней и основного дамаг-спамма.
    rotationChildren.push_back(buildReapBranch(context));

    // 4. [НИЗШИЙ ПРИОРИТЕТ] Автоатака - гарантируем, что персонаж всегда бьет.
    rotationChildren.push_back(CombatCommon::buildEnsureAutoAttackLogic(context));

    auto combatRotationSelector = std::make_unique<SelectorNode>(std::move(rotationChildren));

    // --- Главный узел для боевой логики ---
    // SequenceNode: "Сначала сблизись, А ПОТОМ используй ротацию"
    std::vector<std::unique_ptr<BTNode>> rootChildren;

    // 1. Сближение с целью
    rootChildren.push_back(CombatCommon::buildDefaultEngageLogic(context));

    // 2. Добавляем нашу ротацию следом.
    rootChildren.push_back(std::move(combatRotationSelector));

    // Возвращаем всю боевую логику как одну большую последовательность.
    return std::make_unique<SequenceNode>(std::move(rootChildren));
}

// --- Главный сборщик ---
std::unique_ptr<BTNode> BloodDeathKnightBuilder::buildCombatTree(BTContext& context)
{
    // --- Ветка 1: Логика для состояния "В БОЮ" ---
    // Мы берем всю нашу сложную боевую логику.
    auto inCombatBranch = buildInCombatLogic(context);

    // --- Ветка 2: Логика для состояния "ВНЕ БОЯ" ---
    auto outOfCombatBranch = buildOutOfCombatLogic(context);

    // --- Создаем "стража" для боевой логики ---

    // 1. Создаем лямбда-функцию, которая будет нашим условием: В бою ли персонаж?
    auto isInCombatCondition = [](BTContext& ctx) -> bool
    {
        // Проверяем актуальное состояние.
        return ctx.character->isInCombat();
    };

    // 2. Оборачиваем нашу БОЕВУЮ ветку (`inCombatBranch`) в декоратор.
    //    Теперь эта ветка будет работать до тех пор, пока `isInCombatCondition` возвращает `true`.
    auto guardedInCombatLogic =
        std::make_unique<RunWhileConditionDecorator>(std::move(inCombatBranch), isInCombatCondition);

    // --- Корень дерева: Selector ---
    std::vector<std::unique_ptr<BTNode>> rootChildren;

    // Сначала он попытается выполнить "боевую" ветку.
    // Если мы в бою, guardedInCombatLogic вернет Running/Success/Failure, но Selector не перейдет дальше.
    rootChildren.push_back(std::move(guardedInCombatLogic));

    // Если мы НЕ в бою, guardedInCombatLogic вернет Failure,
    // и Selector перейдет к следующему узлу - логике вне боя.
    rootChildren.push_back(std::move(outOfCombatBranch));

    return std::make_unique<SelectorNode>(std::move(rootChildren));
}