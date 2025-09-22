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
    // Это SequenceNode ("И... И... И..."). Бот должен последовательно выполнить все эти шаги.
    auto engageTargetBranch = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;

        // ШАГ 1: Найти, кто нас атакует.
        // Если никто не атакует, эта ветка провалится.
        children.push_back(std::make_unique<FindAggressorAction>());

        // ШАГ 2: Сократить дистанцию.
        // Используем TeleportToTargetAction для мгновенного сближения.
        // ПРИМЕЧАНИЕ: Здесь можно будет позже добавить проверку на расстояние,
        // чтобы не телепортироваться, если мы уже в мили.
        children.push_back(std::make_unique<TeleportToTargetAction>());

        // ШАГ 3: Убедиться, что мы смотрим на цель.
        // Это "Проверь или Сделай": сначала пытаемся проверить, если не вышло - делаем.
        std::vector<std::unique_ptr<BTNode>> facingChildren;
        facingChildren.push_back(std::make_unique<IsFacingTargetCondition>());  // Проверка
        facingChildren.push_back(std::make_unique<FaceTargetAction>());         // Действие
        children.push_back(std::make_unique<SelectorNode>(std::move(facingChildren)));

        return std::make_unique<SequenceNode>(std::move(children));
    }();

    // --- Ветка 2: Боевая ротация (пока просто автоатака) ---
    // TODO: Здесь будет основная логика использования способностей.
    // Пока что мы просто создадим "заглушку".
    auto combatRotationBranch = []() -> std::unique_ptr<BTNode>
    {
        std::vector<std::unique_ptr<BTNode>> children;

        // Просто для примера. Позже здесь будут CastSpellAction и т.д.
        // Например, можно добавить узел StartAutoAttackAction.

        return std::make_unique<SequenceNode>(std::move(children));
    }();

    // --- Главный узел для боевой логики ---
    // Мы используем Selector ("ИЛИ... ИЛИ...").
    // Сначала бот попытается выполнить "Подготовку к бою".
    // Если она УЖЕ выполнена (например, мы уже стоим лицом к цели),
    // он перейдет к "Боевой ротации".
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(std::move(engageTargetBranch));
    rootChildren.push_back(std::move(combatRotationBranch));

    return std::make_unique<SelectorNode>(std::move(rootChildren));
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