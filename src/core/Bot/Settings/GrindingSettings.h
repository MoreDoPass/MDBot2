// --- НАЧАЛО ФАЙЛА core/Bot/Settings/GrindingSettings.h ---
#pragma once
#include <QString>
#include <vector>
#include <QVariant>

/**
 * @brief Структура для хранения настроек, специфичных для модуля "Гринд мобов".
 */
struct GrindingSettings
{
    /**
     * @brief Путь к файлу с маршрутом для гринда.
     * @details Может быть тот же самый файл, что и для сбора, если нужно.
     */
    QString profilePath;

    /**
     * @brief Список ID NPC, которых нужно атаковать.
     * @details Заполняется из текстового поля в GUI.
     */
    std::vector<int> npcIdsToGrind;

    /**
     * @brief ID заклинания, используемого для "пула" (выманивания) моба.
     * @details Например, ID "Ледяной стрелы" для мага.
     */
    int pullSpellId = 0;

    /**
     * @brief ID еды для восстановления здоровья.
     * @details Используется в ветке отдыха, если здоровье < 50%.
     */
    int foodItemId = 0;

    /**
     * @brief ID напитка для восстановления маны.
     * @details Используется в ветке отдыха, если мана < 50%.
     */
    int drinkItemId = 0;
};

// Регистрируем тип, чтобы его можно было передавать через сигналы Qt
Q_DECLARE_METATYPE(GrindingSettings)
// --- КОНЕЦ ФАЙЛА core/Bot/Settings/GrindingSettings.h ---