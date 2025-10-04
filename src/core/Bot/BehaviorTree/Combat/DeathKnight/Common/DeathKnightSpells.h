// Файл: src/core/Bot/CombatLogic/DeathKnight/Common/DeathKnightSpells.h

#pragma once

#include "core/Bot/BehaviorTree/Combat/Common/CombatUtils.h"  // Для SpellRankInfo
#include <vector>

// Это наш центральный "словарь" для всех общих заклинаний и данных Рыцаря Смерти.
namespace DeathKnightSpells
{

// ЗИМНИЙ ГОРН
inline const std::vector<SpellRankInfo> HORN_OF_WINTER_RANKS = {
    {57623, 75},  // Ранг 2: Horn of Winter
    {57330, 65}   // Ранг 1: Horn of Winter
};

// Если у заклинания есть ранги, они будут здесь
// inline const std::vector<SpellRankInfo> DEATH_STRIKE_RANKS = { ... };

inline const std::vector<SpellRankInfo> ICY_TOUCH_RANKS = {
    {49909, 78},  // Ранг 5: Icy Touch
    {49904, 73},  // Ранг 4: Icy Touch
    {49903, 67},  // Ранг 3: Icy Touch
    {49896, 61},  // Ранг 2: Icy Touch
    {45477, 55}   // Ранг 1: Icy Touch (Минимальный уровень для ДК)
};

// Озноб (Frost Fever) - дебафф, который вешает ЛП
constexpr int FROST_FEVER_DEBUFF_ID = 55095;

inline const std::vector<SpellRankInfo> PLAGUE_STRIKE_RANKS = {
    {49921, 80},  // Ранг 6: Plague Strike
    {49920, 75},  // Ранг 5: Plague Strike
    {49919, 70},  // Ранг 4: Plague Strike
    {49918, 65},  // Ранг 3: Plague Strike
    {49917, 60},  // Ранг 2: Plague Strike
    {45462, 55}   // Ранг 1: Plague Strike
};

// Кровавая Чума (Blood Plague) - дебафф от Удара Чумы
constexpr int BLOOD_PLAGUE_DEBUFF_ID = 55078;

// Удар смерти
inline const std::vector<SpellRankInfo> DEATH_STRIKE_RANKS = {
    {49924, 80},  // Ранг 5: Death Strike
    {49923, 75},  // Ранг 4: Death Strike
    {45463, 70},  // Ранг 3: Death Strike
    {49999, 63},  // Ранг 2: Death Strike
    {49998, 56}   // Ранг 1: Death Strike
};

// Удар в сердце
// Примечание: Уровень 59 был повышен до 60 для контроля логики ротации.
inline const std::vector<SpellRankInfo> HEART_STRIKE_RANKS = {
    {55262, 80},  // Ранг 6: Heart Strike
    {55261, 74},  // Ранг 5: Heart Strike
    {55260, 69},  // Ранг 4: Heart Strike
    {55259, 64},  // Ранг 3: Heart Strike
    {55258, 60}   // Ранг 2: Heart Strike (Скорректирован с 59 до 60 для логики)
};

// Пожинание (Reap) - кастомный скилл (Blood DK)
constexpr int REAP_SPELL_ID = 322772;  // <-- НОВЫЙ ID
}  // namespace DeathKnightSpells