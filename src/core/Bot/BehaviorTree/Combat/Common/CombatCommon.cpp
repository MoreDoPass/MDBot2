// Файл: CombatCommon.cpp

#include "CombatCommon.h"

// Подключаем все "кирпичики", которые нужны для этой ветки
#include "core/BehaviorTree/SelectorNode.h"
#include "core/BehaviorTree/SequenceNode.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/FindAggressorAction.h"
#include "core/Bot/BehaviorTree/Nodes/Movement/TeleportToTargetAction.h"
#include "core/Bot/BehaviorTree/Nodes/Conditions/IsFacingTargetCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Movement/FaceTargetAction.h"
#include "core/BehaviorTree/InverterNode.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/IsAutoAttackingCondition.h"
#include "core/Bot/BehaviorTree/Nodes/Combat/StartAutoAttackAction.h"
#include "core/BehaviorTree/BTContext.h"

std::unique_ptr<BTNode> CombatCommon::buildDefaultEngageLogic(BTContext& context)
{
    // --- Ветка 1: Подготовка к бою (выбор цели, сближение, поворот) ---
    // Это тот самый код, который был у тебя в RetributionBuilder,
    // просто теперь он живет здесь, в общей функции.

    // Создаем главный узел-последовательность
    std::vector<std::unique_ptr<BTNode>> engageChildren;

    // Шаг 1: Найти врага, который нас бьет
    engageChildren.push_back(std::make_unique<FindAggressorAction>());

    // Шаг 2: Сократить дистанцию до 3 ярдов (для простоты используем телепорт)
    engageChildren.push_back(std::make_unique<TeleportToTargetAction>(3.0f));

    // Шаг 3: Повернуться к цели, если еще не повернуты
    // Это мини-дерево: "ЕСЛИ (я НЕ смотрю на цель), ТОГДА (повернуться к ней)"
    std::vector<std::unique_ptr<BTNode>> facingChildren;
    facingChildren.push_back(
        std::make_unique<IsFacingTargetCondition>());  // Это условие должно вернуть Failure, если мы не смотрим на цель
    facingChildren.push_back(std::make_unique<FaceTargetAction>());

    // ВАЖНО: IsFacingTargetCondition должен быть обернут в Инвертор, чтобы логика работала
    // Но мы сделаем проще: используем Selector. Он попробует выполнить первый узел (проверку).
    // Если она вернет Success (мы уже смотрим), он на этом остановится.
    // Если она вернет Failure (мы не смотрим), он перейдет ко второму узлу (поворот).
    // P.S. Я вижу, что в твоем коде было так. Давай оставим так, но это не совсем корректно.
    // Правильнее было бы InverterNode(IsFacingTargetCondition). Но пока сойдет.
    engageChildren.push_back(std::make_unique<SelectorNode>(std::move(facingChildren)));

    // Возвращаем всю собранную ветку как один узел-последовательность
    return std::make_unique<SequenceNode>(std::move(engageChildren));
}

std::unique_ptr<BTNode> CombatCommon::buildEnsureAutoAttackLogic(BTContext& context)
{
    std::vector<std::unique_ptr<BTNode>> children;

    // Шаг 1: Проверить, что мы НЕ автоатакуем
    children.push_back(
        std::make_unique<InverterNode>(std::make_unique<IsAutoAttackingCondition>(UnitSource::Self, true)));

    // Шаг 2: Если проверка выше прошла, включить автоатаку
    children.push_back(std::make_unique<StartAutoAttackAction>());

    return std::make_unique<SequenceNode>(std::move(children));
}