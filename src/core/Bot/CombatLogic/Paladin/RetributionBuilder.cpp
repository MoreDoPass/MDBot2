#include "RetributionBuilder.h"
#include <vector>  // Убедись, что vector подключен

// Включаем стандартные узлы
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/SequenceNode.h"

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

// --- "БАЗА ДАННЫХ": Описываем все ранги "кулака" ---
// Структура для хранения информации об одном ранге.
struct SpellRankInfo
{
    int spellId;        // ID конкретного ранга
    int requiredLevel;  // Уровень, на котором он доступен
};

// Список всех рангов, отсортированный от самого сильного к самому слабому.
// Это единственное место, которое нужно будет обновлять, если изменятся ID или уровни.
const std::vector<SpellRankInfo> BLESSING_OF_MIGHT_RANKS = {
    {48932, 79},  // Ранг 10
    {48931, 73},  // Ранг 9
    {27140, 70},  // Ранг 8 (я ошибся, 20217 - это ранг 8, а не Короли)
    {25291, 60},  // Ранг 7
    {19838, 52},  // Ранг 6
    {19837, 42},  // Ранг 5
    {19836, 32},  // Ранг 4
    {19835, 22},  // Ранг 3
    {19834, 12},  // Ранг 2
    {19740, 4}    // Ранг 1
};

const std::vector<SpellRankInfo> HAMMER_OF_WRATH_RANKS = {
    {48806, 80},  // Ранг 6
    {48805, 74},  // Ранг 5
    {27180, 68},  // Ранг 4
    {24239, 60},  // Ранг 3
    {24274, 52},  // Ранг 2
    {24275, 44}   // Ранг 1
};

const std::vector<SpellRankInfo> EXORCISM_RANKS = {
    {48801, 79},  // Ранг 9
    {48800, 73},  // Ранг 8
    {27138, 68},  // Ранг 7
    {10314, 60},  // Ранг 6
    {10313, 52},  // Ранг 5
    {10312, 44},  // Ранг 4
    {5615, 36},   // Ранг 3
    {5614, 28},   // Ранг 2
    {879, 20}     // Ранг 1
};

// --- "КАЛЬКУЛЯТОР": Функция для выбора лучшего ранга ---
// Она не имеет отношения к Дереву Поведения, это просто чистая C++ логика.
static int findHighestAvailableRankId(int currentLevel, const std::vector<SpellRankInfo>& ranks)
{
    // Идем по списку от лучших рангов к худшим.
    for (const auto& rank : ranks)
    {
        // Находим первый же ранг, который нам по уровню.
        if (currentLevel >= rank.requiredLevel)
        {
            // Это он! Возвращаем его ID.
            return rank.spellId;
        }
    }
    // Если мы прошли весь цикл и ничего не нашли (например, уровень 1-3),
    // значит, нам недоступен ни один ранг.
    return 0;
}

namespace PaladinSpells
{
constexpr int SEAL_OF_RIGHTEOUSNESS = 21084;
constexpr int SEAL_OF_COMMAND = 20375;
}  // namespace PaladinSpells

static std::unique_ptr<BTNode> buildJudgementBranch()
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

// Собирает ветку дерева для использования "Экзорцизма"
static std::unique_ptr<BTNode> buildExorcismBranch(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId = findHighestAvailableRankId(context.character->getLevel(), EXORCISM_RANKS);

    // 3. Собираем саму ветку (SequenceNode)
    std::vector<std::unique_ptr<BTNode>> children;

    constexpr int THE_ART_OF_WAR_PROC_ID = 59578;

    // Условие 1: Мы достигли уровня, когда эта тактика имеет смысл?
    children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 42));

    // Условие 2 (САМОЕ ВАЖНОЕ): У нас есть прок "Искусство войны"?
    children.push_back(std::make_unique<HasBuffCondition>(UnitSource::Self, THE_ART_OF_WAR_PROC_ID, true));

    // Условие 3: Цель в радиусе 30 ярдов?
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(30.0f)); // <-- ПОКА ЗАКОММЕНТИРОВАНО

    // Условие 4: Хватает ли маны?
    // ВАЖНО: Мы передаем сюда ID лучшего ранга, который вычислили ранее.
    // children.push_back(std::make_unique<HasEnoughManaCondition>(bestRankId)); // <-- ПОКА ЗАКОММЕНТИРОВАНО

    // Действие: Кастуем нужный ранг Экзорцизма!
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, bestRankId));

    return std::make_unique<SequenceNode>(std::move(children));
}

// Собирает ветку дерева для использования "Удара воина света"
static std::unique_ptr<BTNode> buildCrusaderStrikeBranch()
{
    // Используем SequenceNode, т.к. все условия должны быть выполнены
    std::vector<std::unique_ptr<BTNode>> children;

    constexpr int CRUSADER_STRIKE_SPELL_ID = 35395;

    // Условие 1: Мы достигли 50-го уровня?
    children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 50));

    // Условие 2: Цель в радиусе удара? (4 ярда)
    // Вам понадобится создать узел IsTargetInRangeCondition, если его еще нет.
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(4.0f)); // <-- ПОКА ЗАКОММЕНТИРОВАНО

    // Условие 3: Скилл не на кулдауне?
    children.push_back(std::make_unique<IsSpellOnCooldownCondition>(CRUSADER_STRIKE_SPELL_ID));

    // Условие 4: Хватает ли маны?
    // Вам понадобится создать узел HasEnoughManaCondition
    // children.push_back(std::make_unique<HasEnoughManaCondition>(CRUSADER_STRIKE_SPELL_ID)); // <-- ПОКА
    // ЗАКОММЕНТИРОВАНО

    // Действие: Если все проверки прошли, бьем!
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::CurrentTarget, CRUSADER_STRIKE_SPELL_ID));

    return std::make_unique<SequenceNode>(std::move(children));
}

// Собирает ветку дерева для использования "Божественной бури"
static std::unique_ptr<BTNode> buildDivineStormBranch()
{
    // Все условия должны быть выполнены, поэтому используем SequenceNode
    std::vector<std::unique_ptr<BTNode>> children;

    constexpr int DIVINE_STORM_SPELL_ID = 53385;

    // Условие 1: Мы достигли 60-го уровня?
    children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 60));

    // Условие 2: Цель в радиусе удара? (4 ярда, как вы и сказали)
    // Узел IsTargetInRangeCondition будет добавлен позже.
    // children.push_back(std::make_unique<IsTargetInRangeCondition>(4.0f)); // <-- ПОКА ЗАКОММЕНТИРОВАНО

    // Условие 3: Скилл не на кулдауне?
    children.push_back(std::make_unique<IsSpellOnCooldownCondition>(DIVINE_STORM_SPELL_ID));

    // Условие 4: Хватает ли маны?
    // Узел HasEnoughManaCondition будет добавлен позже.
    // children.push_back(std::make_unique<HasEnoughManaCondition>(DIVINE_STORM_SPELL_ID)); // <-- ПОКА ЗАКОММЕНТИРОВАНО

    // Действие: Если все проверки прошли, используем бурю!
    children.push_back(std::make_unique<CastSpellAction>(UnitSource::Self, DIVINE_STORM_SPELL_ID));

    return std::make_unique<SequenceNode>(std::move(children));
}

// Собирает ветку дерева для использования "Молота Гнева"
static std::unique_ptr<BTNode> buildHammerOfWrathBranch(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId = findHighestAvailableRankId(context.character->getLevel(), HAMMER_OF_WRATH_RANKS);

    // 2. Если калькулятор вернул 0, значит мы еще не доросли до этого скилла.
    //    Нет смысла строить ветку, просто возвращаем пустоту.
    if (bestRankId == 0)
    {
        return nullptr;
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

// --- Логика ВНЕ боя ---
std::unique_ptr<BTNode> RetributionBuilder::buildOutOfCombatLogic(BTContext& context)
{
    // --- ВЕТКА 1: Логика для уровня 20+ ---
    auto sequenceForLevel20 = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;
        children.push_back(std::make_unique<IsLevelCondition>(UnitSource::Self, ComparisonType::GreaterOrEqual, 20));
        children.push_back(std::make_unique<HasBuffCondition>(UnitSource::Self, PaladinSpells::SEAL_OF_COMMAND, false));

        // --- НОВАЯ СТРОКА ---
        // Перед тем как кастовать, проверяем, готовы ли кулдауны.
        children.push_back(std::make_unique<IsSpellOnCooldownCondition>(PaladinSpells::SEAL_OF_COMMAND));

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

    // --- УМНАЯ Логика для БЛАГОСЛОВЕНИЯ МОГУЩЕСТВА ---

    // 1. Архитектор берет "калькулятор".
    //    Он получает ТЕКУЩИЙ уровень персонажа из контекста и передает его в функцию.
    int bestMightRankId = findHighestAvailableRankId(context.character->getLevel(), BLESSING_OF_MIGHT_RANKS);

    // 2. Архитектор создает пустой вектор для дочерних узлов Selector'а.
    std::vector<std::unique_ptr<BTNode>> rootChildren;

    // 3. Добавляем логику для печатей в первую очередь (высший приоритет).
    rootChildren.push_back(std::move(sequenceForLevel20));
    rootChildren.push_back(std::move(sequenceForLevel1));

    // 4. Архитектор проверяет результат вычислений.
    //    Если "калькулятор" вернул валидный ID (не 0), то строим ветку для баффа.
    if (bestMightRankId != 0)
    {
        // ИСПОЛЬЗУЕМ НАДЕЖНЫЙ СПОСОБ СОЗДАНИЯ ВЕТКИ
        std::vector<std::unique_ptr<BTNode>> mightChildren;
        mightChildren.push_back(std::make_unique<HasBuffCondition>(UnitSource::Self, bestMightRankId, false));
        mightChildren.push_back(std::make_unique<CastSpellAction>(UnitSource::Self, bestMightRankId));

        auto sequenceForMight = std::make_unique<SequenceNode>(std::move(mightChildren));
        rootChildren.push_back(std::move(sequenceForMight));
    }

    // 5. Возвращаем главный Selector, собранный из всех наших веток.
    return std::make_unique<SelectorNode>(std::move(rootChildren));
}

// --- Логика ВНУТРИ боя (ПОКА НЕ РЕАЛИЗОВАНА) ---
std::unique_ptr<BTNode> RetributionBuilder::buildInCombatLogic(BTContext& context)
{
    // --- Ветка 1: Подготовка к бою (выбор цели, сближение, поворот) ---
    // Эта ветка остается без изменений.
    auto engageTargetBranch = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;
        children.push_back(std::make_unique<FindAggressorAction>());
        children.push_back(std::make_unique<TeleportToTargetAction>(3.0f));

        std::vector<std::unique_ptr<BTNode>> facingChildren;
        facingChildren.push_back(std::make_unique<IsFacingTargetCondition>());
        facingChildren.push_back(std::make_unique<FaceTargetAction>());
        children.push_back(std::make_unique<SelectorNode>(std::move(facingChildren)));

        return std::make_unique<SequenceNode>(std::move(children));
    }();

    // --- Ветка 2: Боевая ротация (с ИСПРАВЛЕННОЙ логикой) ---
    std::vector<std::unique_ptr<BTNode>> rotationChildren;

    // ПРИОРИТЕТ №1: Попытаться использовать Правосудие.
    // Вызываем нашу новую функцию, которая вернет готовую ветку для этого скилла.
    rotationChildren.push_back(buildJudgementBranch());

    rotationChildren.push_back(buildHammerOfWrathBranch(context));

    // Попытаться использовать Божественную бурю.
    rotationChildren.push_back(buildDivineStormBranch());

    // ПРИОРИТЕТ №1: Попытаться использовать Удар воина света.
    rotationChildren.push_back(buildCrusaderStrikeBranch());

    // Передаем context в нашу новую функцию.
    rotationChildren.push_back(buildExorcismBranch(context));

    // тогда проверяем и включаем автоатаку.
    // Логика автоатаки, как "запасной" вариант.
    auto autoAttackBranch = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> autoAttackChildren;
        autoAttackChildren.push_back(std::make_unique<IsAutoAttackingCondition>(UnitSource::Self, true));
        autoAttackChildren.push_back(std::make_unique<StartAutoAttackAction>());
        return std::make_unique<SelectorNode>(std::move(autoAttackChildren));
    }();
    rotationChildren.push_back(std::move(autoAttackBranch));

    // Оборачиваем всю ротацию в Selector.
    auto combatRotationSelector = std::make_unique<SelectorNode>(std::move(rotationChildren));

    // --- Главный узел для боевой логики (ИСПРАВЛЕННЫЙ) ---
    // ИСПОЛЬЗУЕМ Sequence ("И... А ПОТОМ..."), а не Selector.
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(std::move(engageTargetBranch));
    rootChildren.push_back(std::move(combatRotationSelector));

    return std::make_unique<SequenceNode>(std::move(rootChildren));
}

// --- Главный сборщик ---
std::unique_ptr<BTNode> RetributionBuilder::buildCombatTree(BTContext& context)
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