// Файл: CombatCommon.h

#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <memory>

class BTContext;

// Наш новый "глобальный ящик с инструментами" для боя.
namespace CombatCommon
{
/**
 * @brief Собирает базовую ветку для начала боя.
 * @details Выполняет последовательность: Найти цель -> Сократить дистанцию -> Повернуться к цели.
 *          Подходит для большинства простых случаев.
 */
std::unique_ptr<BTNode> buildDefaultEngageLogic(BTContext& context);

/**
 * @brief Собирает ветку, которая гарантирует, что автоатака включена.
 * @details Если автоатака выключена, этот узел включит ее.
 */
std::unique_ptr<BTNode> buildEnsureAutoAttackLogic(BTContext& context);
}  // namespace CombatCommon