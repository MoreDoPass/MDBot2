#include "BehaviorTreeBuilder.h"
#include "core/BehaviorTree/BTContext.h"
#include "core/BehaviorTree/SelectorNode.h"
#include <QLoggingCategory>
#include <vector>

// Подключаем всех наших "специалистов-строителей"
#include "core/Bot/BehaviorTree/SystemBuilder.h"
#include "core/Bot/BehaviorTree/ModuleBuilder.h"
#include "core/Bot/BehaviorTree/CombatBuilder.h"

Q_LOGGING_CATEGORY(logBTBuilder, "mdbot.bot.bt.builder")

std::unique_ptr<BTNode> BehaviorTreeBuilder::build(BTContext& context)
{
    qCInfo(logBTBuilder) << "Assembling final Behavior Tree...";

    // --- Шаг 1: Построить ветку системных проверок (высший приоритет) ---
    qCDebug(logBTBuilder) << "Step 1: Building system/safety branch...";
    std::unique_ptr<BTNode> systemBranch = SystemBuilder::build(context);

    // --- Шаг 2: Построить "инструмент" - боевую логику ---
    // Эта логика сама по себе не выполняется, она будет передана в модуль.
    qCDebug(logBTBuilder) << "Step 2: Building combat logic sub-tree...";
    std::unique_ptr<BTNode> combatBranch = CombatBuilder::buildCombatLogic(context);

    // --- Шаг 3: Построить ветку основной деятельности (низший приоритет) ---
    // Передаем в нее уже готовую боевую логику.
    qCDebug(logBTBuilder) << "Step 3: Building main module branch...";
    std::unique_ptr<BTNode> moduleBranch = ModuleBuilder::build(context, std::move(combatBranch));

    // Проверяем, что модуль успешно построился
    if (!moduleBranch)
    {
        qCCritical(logBTBuilder) << "ModuleBuilder failed to create a module branch. Aborting tree assembly.";
        return nullptr;
    }

    // --- Шаг 4: Собрать финальное дерево из веток ---
    qCDebug(logBTBuilder) << "Step 4: Assembling branches into final SelectorNode...";
    auto rootChildren = std::vector<std::unique_ptr<BTNode>>();

    // ПРИОРИТЕТ 1: Системные проверки.
    rootChildren.push_back(std::move(systemBranch));

    // ПРИОРИТЕТ 2: Основная работа.
    rootChildren.push_back(std::move(moduleBranch));

    // Selector гарантирует, что если сработает что-то в systemBranch (например, смерть),
    // то moduleBranch в этом тике даже не будет запущен.
    auto rootNode = std::make_unique<SelectorNode>(std::move(rootChildren));

    qCInfo(logBTBuilder) << "Behavior Tree assembled successfully!";
    return rootNode;
}