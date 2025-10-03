// Файл: src/core/Bot/CombatLogic/Paladin/Common/PaladinSpells.h

#pragma once

#include "core/Bot/CombatLogic/Common/CombatUtils.h"  // Подключаем, чтобы знать, что такое SpellRankInfo
#include <vector>

// Это наш центральный "словарь" для всех общих заклинаний и данных Паладина.
// Если нужно поменять ID или добавить ранг, ты будешь делать это только здесь.
namespace PaladinSpells
{
// --- ID ОТДЕЛЬНЫХ ЗАКЛИНАНИЙ ---

// Печати
constexpr int SEAL_OF_RIGHTEOUSNESS = 21084;
constexpr int SEAL_OF_COMMAND = 20375;
// В будущем сюда можно будет добавить:
// constexpr int SEAL_OF_VENGEANCE = 31801;

// Правосудие (используем ID общего спелла)
constexpr int JUDGEMENT = 20271;

// --- СПИСКИ РАНГОВ ОБЩИХ ЗАКЛИНАНИЙ ---

// [ВЫНЕСЕНО СЮДА] Список рангов для Молота Гнева.
// Ключевое слово "inline" - это современный способ C++ безопасно объявлять
// такие списки в заголовочных файлах, избегая ошибок компиляции.
inline const std::vector<SpellRankInfo> HAMMER_OF_WRATH_RANKS = {
    {48806, 80},  // Ранг 6
    {48805, 74},  // Ранг 5
    {27180, 68},  // Ранг 4
    {24239, 60},  // Ранг 3
    {24274, 52},  // Ранг 2
    {24275, 44}   // Ранг 1
};

inline const std::vector<SpellRankInfo> BLESSING_OF_MIGHT_RANKS = {
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

inline const std::vector<SpellRankInfo> BLESSING_OF_KINGS_RANKS = {
    {20217, 20}  // Ранг 1
};

inline const std::vector<SpellRankInfo> BLESSING_OF_WISDOM_RANKS = {
    {48936, 77},  // Ранг 9
    {48935, 71},  // Ранг 8
    {27142, 65},  // Ранг 7
    {25290, 60},  // Ранг 6
    {19854, 54},  // Ранг 5
    {19853, 44},  // Ранг 4
    {19852, 34},  // Ранг 3
    {19850, 24},  // Ранг 2
    {19742, 14}   // Ранг 1
};
}  // namespace PaladinSpells