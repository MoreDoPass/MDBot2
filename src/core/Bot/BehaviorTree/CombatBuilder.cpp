#include "CombatBuilder.h"
#include "core/Bot/Settings/BotSettings.h"
#include "core/Bot/CombatLogic/Paladin/ProtectionPaladinBuilder/ProtectionPaladinBuilder.h"
#include "core/Bot/CombatLogic/Paladin/RetributionPaladinBuilder/RetributionPaladinBuilder.h"
#include "core/Bot/CombatLogic/DeathKnight/Blood/BloodDeathKnightBuilder.h"
#include "core/BehaviorTree/SequenceNode.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logCombatBuilder, "mdbot.bot.bt.combatbuilder")

std::unique_ptr<BTNode> CombatBuilder::buildCombatLogic(BTContext& context)
{
    const CharacterSpec spec = context.settings.spec;
    qCInfo(logCombatBuilder) << "Building combat logic for spec:" << static_cast<int>(spec);

    switch (spec)
    {
        case CharacterSpec::PaladinProtection:
            return ProtectionPaladinBuilder::buildCombatTree(context);
        case CharacterSpec::PaladinRetribution:
            return RetributionPaladinBuilder::buildCombatTree(context);
        case CharacterSpec::DeathKnightBlood:
            return BloodDeathKnightBuilder::buildCombatTree(context);
        default:
            qCCritical(logCombatBuilder) << "Combat logic for spec" << static_cast<int>(spec)
                                         << " is not implemented yet.";
            return std::make_unique<SequenceNode>(std::vector<std::unique_ptr<BTNode>>{});
    }
}