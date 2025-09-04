#pragma once
#include <QString>
#include <vector>
#include <QVariant>

/**
 * @brief Структура для хранения настроек, специфичных для модуля "Сбор ресурсов".
 */
struct GatheringSettings
{
    /**
     * @brief Путь к XML-файлу с маршрутом (точками для облета).
     */
    QString profilePath;

    /**
     * @brief Список ID объектов (руды, травы), которые нужно собирать.
     */
    std::vector<int> nodeIdsToGather;
};

// Регистрируем тип, чтобы его можно было передавать через сигналы Qt
Q_DECLARE_METATYPE(GatheringSettings)