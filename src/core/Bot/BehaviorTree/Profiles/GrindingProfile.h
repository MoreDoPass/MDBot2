// --- НАЧАЛО ФАЙЛА core/Bot/Profiles/GrindingProfile.h ---
#pragma once
#include "shared/Utils/Vector.h"  // Для Vector3
#include <QString>
#include <vector>

/**
 * @struct GrindingProfile
 * @brief "Чертеж" для задачи гринда мобов.
 * @details Содержит всю информацию, загруженную из JSON-файла:
 *          имя, маршрут и список ID мобов для атаки.
 */
struct GrindingProfile
{
    /// @brief Имя профиля для отображения в логах или GUI.
    QString profileName = "Unnamed Grinding Profile";

    /// @brief Маршрут, по которому будет двигаться бот.
    std::vector<Vector3> path;

    /// @brief Список ID мобов, которых нужно атаковать.
    std::vector<int> mobIdsToGrind;
};
// --- КОНЕЦ ФАЙЛА ---