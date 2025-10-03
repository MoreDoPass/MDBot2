// Файл: src/core/Bot/CombatLogic/Paladin/Common/PaladinCommon.h

#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <memory>
#include "core/Bot/CombatLogic/Common/CombatUtils.h"

// Предварительное объявление, чтобы не подключать полный заголовок BTContext.h
class BTContext;

// Пространство имен, чтобы сгруппировать все наши общие функции для паладинов.
namespace PaladinCommon
{
/**
 * @brief Собирает ветку печати.
 * @details
 *  - На уровнях 1-19 использует Печать праведности.
 *  - На уровнях 20+ использует Печать повиновения.
 * @param context Контекст дерева.
 * @return Указатель на узел Selector, содержащий всю эту логику.
 */
std::unique_ptr<BTNode> buildDefaultSealLogic(BTContext& context);

/**
 * @brief Собирает ветку для использования Правосудия.
 */
std::unique_ptr<BTNode> buildJudgementLogic(BTContext& context);

std::unique_ptr<BTNode> buildHammerOfWrathLogic(BTContext& context);

std::unique_ptr<BTNode> buildSelfBlessingLogic(BTContext& context, const std::vector<SpellRankInfo>& ranks);
}  // namespace PaladinCommon