// Файл: src/core/Bot/CombatLogic/Common/CombatUtils.h

#pragma once
#include <vector>

/**
 * @struct SpellRankInfo
 * @brief Универсальная структура для хранения информации о рангах любого заклинания.
 */
struct SpellRankInfo
{
    int spellId;
    int requiredLevel;
};

// Пространство имен для универсальных, не связанных с Деревом Поведения,
// вспомогательных функций для боя.
namespace CombatUtils
{
/**
 * @brief "Калькулятор" для выбора лучшего доступного ранга заклинания по уровню.
 * @param currentLevel Текущий уровень персонажа.
 * @param ranks Список всех рангов заклинания, отсортированный от сильного к слабому.
 * @return ID лучшего доступного ранга или 0, если ни один не доступен.
 */
int findHighestAvailableRankId(int currentLevel, const std::vector<SpellRankInfo>& ranks);

}  // namespace CombatUtils