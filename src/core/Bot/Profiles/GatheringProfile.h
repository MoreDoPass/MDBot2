#pragma once

#include "shared/Utils/Vector.h"  // Для Vector3
#include <vector>
#include <QString>

/**
 * @struct GatheringProfile
 * @brief Структура данных для хранения информации из профиля сбора.
 * @details Это простой "глупый" контейнер данных, который ProfileManager
 *          заполняет при парсинге JSON-файла.
 */
struct GatheringProfile
{
    /**
     * @brief Определяет, с какой точки маршрута начинать движение.
     */
    enum class StartPointLogic
    {
        FromTheFirst,   ///< Всегда начинать с первой точки в файле.
        FromTheNearest  ///< Найти ближайшую к персонажу точку и начать с нее.
    };

    // --- Настройки, загружаемые из профиля ---
    // Эти поля будут заполняться, только если они есть в JSON.
    // Если нет, будут использованы значения по умолчанию.
    QString profileName = "Unnamed Profile";  ///< Имя профиля для отображения.

    // путь к файлу маршрута
    QString sourceFilePath;

    StartPointLogic startLogic = StartPointLogic::FromTheNearest;  ///< Логика выбора стартовой точки.
    std::vector<int> nodeIdsToGather;                              ///< Список Entry ID руды/травы (если указан).

    // --- Основные данные ---
    // Это поле будет заполняться всегда из твоего JSON.
    std::vector<Vector3> path;  ///< Список точек (маршрут), по которому будет двигаться бот.
};