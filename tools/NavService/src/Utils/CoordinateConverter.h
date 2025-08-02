#pragma once

#include "Vector.h"
#include <QString>

/**
 * @class CoordinateConverter
 * @brief Класс для преобразования координат между системами WoW и Recast.
 *
 * WoW использует правую систему координат с осью Y вверх,
 * а Recast использует левую систему координат с осью Y вверх.
 * Этот класс обеспечивает корректное преобразование между системами.
 */
class CoordinateConverter
{
   public:
    /**
     * @brief Преобразует координаты из системы WoW в систему Recast.
     *
     * @param wowCoords Координаты в системе WoW
     * @return Координаты в системе Recast
     */
    static Vector3 wowToRecast(const Vector3& wowCoords);

    /**
     * @brief Преобразует координаты из системы Recast в систему WoW.
     *
     * @param recastCoords Координаты в системе Recast
     * @return Координаты в системе WoW
     */
    static Vector3 recastToWow(const Vector3& recastCoords);

    /**
     * @brief Преобразует координаты из системы WoW в систему Recast с учетом масштаба.
     *
     * @param wowCoords Координаты в системе WoW
     * @param scale Масштабный коэффициент
     * @return Координаты в системе Recast
     */
    static Vector3 wowToRecast(const Vector3& wowCoords, float scale);

    /**
     * @brief Преобразует координаты из системы Recast в систему WoW с учетом масштаба.
     *
     * @param recastCoords Координаты в системе Recast
     * @param scale Масштабный коэффициент
     * @return Координаты в системе WoW
     */
    static Vector3 recastToWow(const Vector3& recastCoords, float scale);

    /**
     * @brief Преобразует вектор направления из системы WoW в систему Recast.
     *
     * @param wowDirection Вектор направления в системе WoW
     * @return Вектор направления в системе Recast
     */
    static Vector3 wowDirectionToRecast(const Vector3& wowDirection);

    /**
     * @brief Преобразует вектор направления из системы Recast в систему WoW.
     *
     * @param recastDirection Вектор направления в системе Recast
     * @return Вектор направления в системе WoW
     */
    static Vector3 recastDirectionToWow(const Vector3& recastDirection);

    /**
     * @brief Проверяет, находятся ли координаты в допустимом диапазоне WoW.
     *
     * @param wowCoords Координаты для проверки
     * @return true если координаты в допустимом диапазоне
     */
    static bool isValidWowCoordinates(const Vector3& wowCoords);

    /**
     * @brief Проверяет, находятся ли координаты в допустимом диапазоне Recast.
     *
     * @param recastCoords Координаты для проверки
     * @return true если координаты в допустимом диапазоне
     */
    static bool isValidRecastCoordinates(const Vector3& recastCoords);

    /**
     * @brief Получает информацию о преобразовании координат.
     *
     * @return Строка с информацией о системах координат
     */
    static QString getCoordinateSystemInfo();

   private:
    // Константы для преобразования координат
    static constexpr float WOW_TO_RECAST_SCALE = 1.0f;         // Масштабный коэффициент
    static constexpr float MAX_WOW_COORDINATE = 100000.0f;     // Максимальная координата в WoW
    static constexpr float MAX_RECAST_COORDINATE = 100000.0f;  // Максимальная координата в Recast
};