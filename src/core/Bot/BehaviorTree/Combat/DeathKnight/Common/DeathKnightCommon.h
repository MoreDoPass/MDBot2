// Файл: src/core/Bot/CombatLogic/DeathKnight/Common/DeathKnightCommon.h

#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <memory>
// #include "core/Bot/CombatLogic/Common/CombatUtils.h" // Если нужен SpellRankInfo, он уже есть через DeathKnightSpells

class BTContext;

/**
 * @namespace DeathKnightCommon
 * @brief Пространство имен для общих функций-строителей дерева поведения Рыцаря Смерти.
 */
namespace DeathKnightCommon
{
/**
 * @brief Собирает ветку для использования Ледяного Прикосновения (Icy Touch).
 * @details
 *  - Вычисляет лучший ранг на основе уровня.
 *  - Проверяет, что на цели НЕТ дебаффа Озноб (Frost Fever).
 *  - Кастует Ледяное Прикосновение.
 * @param context Контекст дерева.
 * @return Указатель на узел SequenceNode.
 */
std::unique_ptr<BTNode> buildIcyTouchLogic(BTContext& context);

/**
 * @brief Собирает ветку для использования Удара Чумы.
 * @details Использует PLAGUE_STRIKE_SPELL_ID, чтобы наложить дебафф BLOOD_PLAGUE_DEBUFF_ID.
 *          Условие: Выполняет каст ТОЛЬКО если на цели НЕТ дебаффа Кровавая Чума.
 * @param context Контекст дерева.
 * @return Указатель на узел SequenceNode, содержащий эту логику.
 */
std::unique_ptr<BTNode> buildPlagueStrikeLogic(BTContext& context);

/**
 * @brief Собирает ветку для использования Удара Смерти (Death Strike).
 * @details
 *          Выполняет каст, если соблюдены его личные условия (радиус, руны).
 *          Проверки на болезни (Озноб/КЧ) выполняются узлами с более высоким приоритетом.
 * @param context Контекст дерева.
 * @return Указатель на узел SequenceNode, содержащий эту логику.
 */
std::unique_ptr<BTNode> buildDeathStrikeLogic(BTContext& context);

/**
 * @brief Собирает ветку для использования Зимнего Горна (Horn of Winter).
 * @details Выполняет бафф, если он отсутствует на персонаже.
 * @param context Контекст дерева.
 * @return Указатель на узел SequenceNode.
 */
std::unique_ptr<BTNode> buildHornOfWinterLogic(BTContext& context);

}  // namespace DeathKnightCommon