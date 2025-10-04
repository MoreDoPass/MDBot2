#include "SystemBuilder.h"
#include "core/BehaviorTree/BTContext.h"
#include "core/BehaviorTree/SequenceNode.h"
#include "core/BehaviorTree/SelectorNode.h"
#include "core/Bot/BehaviorTree/Nodes/Utility/WaitAction.h"
#include <QLoggingCategory>
#include <vector>

// изменения начало
// УДАЛЯЕМ несуществующий инклюд
// #include "core/Bot/BehaviorTree/Nodes/Conditions/IsDeadCondition.h"

// ДОБАВЛЯЕМ существующий, универсальный инклюд
#include "core/Bot/BehaviorTree/Nodes/Conditions/IsHealthCondition.h"
// изменения конец

Q_LOGGING_CATEGORY(logSystemBuilder, "mdbot.bot.bt.systembuilder")

std::unique_ptr<BTNode> SystemBuilder::build(BTContext& context)
{
    qCInfo(logSystemBuilder) << "Building system/safety behavior tree branch...";
    auto rootChildren = std::vector<std::unique_ptr<BTNode>>();

    // --- Ветка 1: Проверка на смерть ---
    {
        auto deathSequence = std::vector<std::unique_ptr<BTNode>>();

        // изменения начало
        // Условие: наше (Self) абсолютное (Absolute) здоровье равно (Equal) нулю?
        deathSequence.push_back(std::make_unique<IsHealthCondition>(UnitSource::Self, ComparisonType::Equal,
                                                                    HealthCheckType::Absolute, 0.0f));
        // изменения конец

        // Действие: если да, то просто ждем 5 секунд (пока это заглушка)
        // В будущем здесь будет логика воскрешения.
        qCDebug(logSystemBuilder) << "Creating 'On Death' branch.";
        deathSequence.push_back(std::make_unique<WaitAction>(5000.0f));

        rootChildren.push_back(std::make_unique<SequenceNode>(std::move(deathSequence)));
    }

    // --- Сюда в будущем можно будет добавлять другие проверки ---
    // {
    //     auto playerThreatSequence = ...
    //     rootChildren.push_back(std::move(playerThreatSequence));
    // }

    // Все системные проверки заворачиваем в Selector.
    // Он выполнит ПЕРВУЮ сработавшую проверку (например, если мы мертвы,
    // он не будет проверять угрозу от игроков).
    return std::make_unique<SelectorNode>(std::move(rootChildren));
}