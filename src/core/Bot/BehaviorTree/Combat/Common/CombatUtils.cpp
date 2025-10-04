// Файл: src/core/Bot/CombatLogic/Common/CombatUtils.cpp

#include "CombatUtils.h"

// Мы должны указать, что эта функция принадлежит пространству имен CombatUtils
namespace CombatUtils
{
// Реализация нашей функции-калькулятора
int findHighestAvailableRankId(int currentLevel, const std::vector<SpellRankInfo>& ranks)
{
    // Идем по списку от лучших рангов к худшим.
    for (const auto& rank : ranks)
    {
        // Находим первый же ранг, который нам по уровню.
        if (currentLevel >= rank.requiredLevel)
        {
            // Это он! Возвращаем его ID.
            return rank.spellId;
        }
    }

    // Если мы прошли весь цикл и ничего не нашли (например, уровень 1-3),
    // значит, нам недоступен ни один ранг.
    return 0;
}

}  // namespace CombatUtils