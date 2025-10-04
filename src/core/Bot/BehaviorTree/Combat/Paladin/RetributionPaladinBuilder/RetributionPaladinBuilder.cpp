#include "RetributionPaladinBuilder.h"
#include <vector>  // Убедись, что vector подключен

// Включаем стандартные узлы
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/SequenceNode.h"

#include "core/Bot/BehaviorTree/Combat/Common/CombatUtils.h"
#include "core/Bot/BehaviorTree/Combat/Common/CombatCommon.h"
#include "core/Bot/BehaviorTree/Combat/Paladin/Common/PaladinCommon.h"
#include "core/Bot/BehaviorTree/Combat/Paladin/Common/PaladinSpells.h"
// Включаем наши "кирпичики"
#include "core/Bot/BehaviorTree/Nodes/Combat/IsLevelCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/HasBuffCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/CastSpellAction.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/IsInCombatCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/FindAggressorAction.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/IsSpellOnCooldownCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Conditions/IsFacingTargetCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Movement/FaceTargetAction.h"
#include "core/Bot/BehaviorTree/Nodes/Movement/TeleportToTargetAction.h"  // Убедитесь, что он подключен
#include "core/Bot/BehaviorTree/Nodes/Combat/StartAutoAttackAction.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/IsAutoAttackingCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Conditions/IsHealthCondition.h"
#include "core/BehaviorTree/RunWhileConditionDecorator.h"
#include "core/Bot/BehaviorTree/Nodes/Targeting/HasTargetCondition.h"

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

static std::unique_ptr<BTNode> buildExorcismBranch(BTContext& context)
{
    // 1. "Калькулятор" вычисляет лучший ранг на основе ТЕКУЩЕГО уровня персонажа.
    int bestRankId = CombatUtils::findHighestAvailableRankId(context.character->getLevel(), EXORCISM_RANKS);

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

// --- Логика ВНЕ боя ---
std::unique_ptr<BTNode> RetributionPaladinBuilder::buildOutOfCombatLogic(BTContext& context)
{
    // Создаем список для веток нашего дерева ("ИЛИ ... ИЛИ ...")
    std::vector<std::unique_ptr<BTNode>> rootChildren;
    rootChildren.push_back(PaladinCommon::buildDefaultSealLogic(context));

    // 2. [ХАРДКОД] Мы, как ретрик, хотим баффнуть себе "Могущество".
    // Мы берем ОБЩИЙ инструмент и передаем в него ДАННЫЕ для "Могущества".
    rootChildren.push_back(PaladinCommon::buildSelfBlessingLogic(context, PaladinSpells::BLESSING_OF_MIGHT_RANKS));
    return std::make_unique<SelectorNode>(std::move(rootChildren));
}

std::unique_ptr<BTNode> RetributionPaladinBuilder::buildInCombatLogic(BTContext& context)
{
    // Собираем само дерево ротации, которое остаётся уникальным для ретрика.
    std::vector<std::unique_ptr<BTNode>> rotationChildren;

    rotationChildren.push_back(PaladinCommon::buildJudgementLogic(context));
    rotationChildren.push_back(PaladinCommon::buildHammerOfWrathLogic(context));
    rotationChildren.push_back(buildDivineStormBranch());
    rotationChildren.push_back(buildCrusaderStrikeBranch());
    rotationChildren.push_back(buildExorcismBranch(context));

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
std::unique_ptr<BTNode> RetributionPaladinBuilder::buildCombatTree(BTContext& context)
{
    // Создаем корневой узел-селектор, который будет выбирать первое успешное действие.
    auto rootChildren = std::vector<std::unique_ptr<BTNode>>();

    // --- Приоритет 1: Мы УЖЕ в бою ИЛИ у нас есть ЦЕЛЬ-ЮНИТ для атаки ---
    // Эта ветка объединяет и ведение боя, и его инициацию.
    {
        auto sequenceChildren = std::vector<std::unique_ptr<BTNode>>();

        // Условие-ОР: Эта ветка сработает, если выполняется ХОТЯ БЫ ОДНО из двух:
        // 1. Мы уже находимся в бою.
        // 2. У нас есть цель, и эта цель является ЮНИТОМ (не рудой, не травой и т.д.).
        {
            auto selectorChildren = std::vector<std::unique_ptr<BTNode>>();
            selectorChildren.push_back(std::make_unique<IsInCombatCondition>(UnitSource::Self));
            // КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: Проверяем не просто наличие цели, а наличие цели типа UNIT.
            // Это защищает нас от попыток атаковать руду в модуле сбора.
            selectorChildren.push_back(std::make_unique<HasTargetCondition>(GameObjectType::Unit));
            sequenceChildren.push_back(std::make_unique<SelectorNode>(std::move(selectorChildren)));
        }

        // Действие: Если условие выше выполнено, запускаем нашу стандартную боевую логику.
        // Она сама разберется, нужно ли подбегать к цели (`buildDefaultEngageLogic`) или уже бить.
        sequenceChildren.push_back(buildInCombatLogic(context));
        rootChildren.push_back(std::make_unique<SequenceNode>(std::move(sequenceChildren)));
    }

    // --- Приоритет 2: Мы вне боя и без цели ---
    // Если первая ветка провалилась, значит, мы точно вне боя и у нас нет враждебной цели.
    // Запускаем логику баффов, печатей и т.д.
    rootChildren.push_back(buildOutOfCombatLogic(context));

    return std::make_unique<SelectorNode>(std::move(rootChildren));
}