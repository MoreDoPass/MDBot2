#include "CoordinateConverter.h"
#include "Logger.h"
#include <cmath>

Vector3 CoordinateConverter::wowToRecast(const Vector3& wowCoords)
{
    return wowToRecast(wowCoords, WOW_TO_RECAST_SCALE);
}

Vector3 CoordinateConverter::recastToWow(const Vector3& recastCoords)
{
    return recastToWow(recastCoords, WOW_TO_RECAST_SCALE);
}

Vector3 CoordinateConverter::wowToRecast(const Vector3& wowCoords, float scale)
{
    // WoW использует правую систему координат: X (восток), Y (север), Z (вверх)
    // Recast использует левую систему координат: X (восток), Z (север), Y (вверх)
    // Преобразование: X -> X, Y -> Z, Z -> Y

    Vector3 recastCoords;
    recastCoords.x = wowCoords.x * scale;
    recastCoords.y = wowCoords.z * scale;  // Z в WoW становится Y в Recast
    recastCoords.z = wowCoords.y * scale;  // Y в WoW становится Z в Recast

    qCDebug(navService) << "Преобразование WoW -> Recast:"
                        << "WoW(" << wowCoords.x << "," << wowCoords.y << "," << wowCoords.z << ")"
                        << "-> Recast(" << recastCoords.x << "," << recastCoords.y << "," << recastCoords.z << ")";

    return recastCoords;
}

Vector3 CoordinateConverter::recastToWow(const Vector3& recastCoords, float scale)
{
    // Обратное преобразование: X -> X, Z -> Y, Y -> Z

    Vector3 wowCoords;
    wowCoords.x = recastCoords.x / scale;
    wowCoords.y = recastCoords.z / scale;  // Z в Recast становится Y в WoW
    wowCoords.z = recastCoords.y / scale;  // Y в Recast становится Z в WoW

    qCDebug(navService) << "Преобразование Recast -> WoW:"
                        << "Recast(" << recastCoords.x << "," << recastCoords.y << "," << recastCoords.z << ")"
                        << "-> WoW(" << wowCoords.x << "," << wowCoords.y << "," << wowCoords.z << ")";

    return wowCoords;
}

Vector3 CoordinateConverter::wowDirectionToRecast(const Vector3& wowDirection)
{
    // Для векторов направления применяется то же преобразование
    return wowToRecast(wowDirection);
}

Vector3 CoordinateConverter::recastDirectionToWow(const Vector3& recastDirection)
{
    // Для векторов направления применяется то же преобразование
    return recastToWow(recastDirection);
}

bool CoordinateConverter::isValidWowCoordinates(const Vector3& wowCoords)
{
    // Проверяем, что координаты находятся в допустимом диапазоне
    if (std::abs(wowCoords.x) > MAX_WOW_COORDINATE || std::abs(wowCoords.y) > MAX_WOW_COORDINATE ||
        std::abs(wowCoords.z) > MAX_WOW_COORDINATE)
    {
        qCWarning(navService) << "Координаты WoW вне допустимого диапазона:"
                              << QString("(%1, %2, %3)").arg(wowCoords.x).arg(wowCoords.y).arg(wowCoords.z);
        return false;
    }

    // Проверяем на NaN и бесконечность
    if (std::isnan(wowCoords.x) || std::isnan(wowCoords.y) || std::isnan(wowCoords.z) || std::isinf(wowCoords.x) ||
        std::isinf(wowCoords.y) || std::isinf(wowCoords.z))
    {
        qCWarning(navService) << "Координаты WoW содержат NaN или бесконечность:"
                              << QString("(%1, %2, %3)").arg(wowCoords.x).arg(wowCoords.y).arg(wowCoords.z);
        return false;
    }

    return true;
}

bool CoordinateConverter::isValidRecastCoordinates(const Vector3& recastCoords)
{
    // Проверяем, что координаты находятся в допустимом диапазоне
    if (std::abs(recastCoords.x) > MAX_RECAST_COORDINATE || std::abs(recastCoords.y) > MAX_RECAST_COORDINATE ||
        std::abs(recastCoords.z) > MAX_RECAST_COORDINATE)
    {
        qCWarning(navService) << "Координаты Recast вне допустимого диапазона:"
                              << QString("(%1, %2, %3)").arg(recastCoords.x).arg(recastCoords.y).arg(recastCoords.z);
        return false;
    }

    // Проверяем на NaN и бесконечность
    if (std::isnan(recastCoords.x) || std::isnan(recastCoords.y) || std::isnan(recastCoords.z) ||
        std::isinf(recastCoords.x) || std::isinf(recastCoords.y) || std::isinf(recastCoords.z))
    {
        qCWarning(navService) << "Координаты Recast содержат NaN или бесконечность:"
                              << QString("(%1, %2, %3)").arg(recastCoords.x).arg(recastCoords.y).arg(recastCoords.z);
        return false;
    }

    return true;
}

QString CoordinateConverter::getCoordinateSystemInfo()
{
    return QString(
               "Системы координат:\n"
               "WoW: правая система (X-восток, Y-север, Z-вверх)\n"
               "Recast: левая система (X-восток, Z-север, Y-вверх)\n"
               "Масштаб: %1\n"
               "Максимальные координаты WoW: ±%2\n"
               "Максимальные координаты Recast: ±%3")
        .arg(WOW_TO_RECAST_SCALE)
        .arg(MAX_WOW_COORDINATE)
        .arg(MAX_RECAST_COORDINATE);
}