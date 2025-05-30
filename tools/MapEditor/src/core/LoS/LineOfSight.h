#pragma once

#include <QVector3D>
#include <QList>
#include <QLoggingCategory>
// Forward declaration, если MapData.h здесь не нужен целиком,
// но для Obstacle он понадобится.
// Либо включить "core/MapData/MapData.h" если он легковесный.
// Пока что включим, так как Obstacle там определен полностью.
#include "core/MapData/MapData.h"  // Для доступа к структуре Obstacle

Q_DECLARE_LOGGING_CATEGORY(losLog)

namespace Core
{
namespace LoS
{

/**
 * @brief Проверяет пересечение луча с AABB (Axis-Aligned Bounding Box) препятствия.
 * Использует Slab method.
 * @param rayOrigin Начальная точка луча.
 * @param rayDirection Нормализованное направление луча.
 * @param obstacle Препятствие для проверки.
 * @param tIntersectionMin Выходной параметр: расстояние до ближайшей точки пересечения (вход в AABB).
 * @param tIntersectionMax Выходной параметр: расстояние до дальней точки пересечения (выход из AABB).
 * @return true, если луч пересекает AABB, иначе false.
 */
bool intersectRayAABB(const QVector3D& rayOrigin, const QVector3D& rayDirection, const Obstacle& obstacle,
                      float& tIntersectionMin, float& tIntersectionMax);

/**
 * @brief Проверяет прямую видимость между двумя точками, используя AABB для всех препятствий.
 * @param pointA Начальная точка отрезка.
 * @param pointB Конечная точка отрезка.
 * @param allObstacles Список всех препятствий на карте.
 * @return true, если между pointA и pointB нет препятствий (их AABB), иначе false.
 */
bool hasLineOfSightAABB(const QVector3D& pointA, const QVector3D& pointB, const QList<Obstacle>& allObstacles);

/**
 * @brief Находит ближайшее пересечение луча с AABB препятствий.
 * @param rayOrigin Начальная точка луча.
 * @param rayDirection Нормализованное направление луча.
 * @param allObstacles Список всех препятствий на карте.
 * @param maxDistance Максимальное расстояние для проверки пересечения.
 * @param hitObstacle Выходной параметр: указатель на препятствие, с которым произошло ближайшее пересечение.
 * @param hitPoint Выходной параметр: точка ближайшего пересечения.
 * @param hitDistance Выходной параметр: расстояние до точки ближайшего пересечения.
 * @return true, если пересечение найдено в пределах maxDistance, иначе false.
 */
bool findClosestAABBIntersection(const QVector3D& rayOrigin, const QVector3D& rayDirection,
                                 const QList<Obstacle>& allObstacles, float maxDistance, const Obstacle*& hitObstacle,
                                 QVector3D& hitPoint, float& hitDistance);

// --- Функции для более точной проверки видимости (пока скелеты) ---

/**
 * @brief Проверяет пересечение луча с полигональной призмой (основание + высота).
 * Детали реализации этой функции будут добавлены позже.
 * @param rayOrigin Начальная точка луча.
 * @param rayDirection Нормализованное направление луча.
 * @param obstacle Препятствие (ожидается, что оно имеет baseVertices и obstacleHeight).
 * @param tEnter Выходной параметр: расстояние до точки входа в призму.
 * @param tExit Выходной параметр: расстояние до точки выхода из призмы.
 * @return true, если луч пересекает призму, иначе false.
 */
bool intersectRayPolygonPrism(const QVector3D& rayOrigin, const QVector3D& rayDirection, const Obstacle& obstacle,
                              float& tEnter, float& tExit);

/**
 * @brief Проверяет пересечение луча с произвольным 3D мешем (если shapeVertices определяют меш).
 * Детали реализации этой функции будут добавлены позже.
 * @param rayOrigin Начальная точка луча.
 * @param rayDirection Нормализованное направление луча.
 * @param obstacle Препятствие (ожидается, что оно имеет shapeVertices, образующие меш).
 * @param tEnter Выходной параметр: расстояние до точки входа в меш.
 * @param tExit Выходной параметр: расстояние до точки выхода из меша.
 * @return true, если луч пересекает меш, иначе false.
 */
bool intersectRayGeneralShape(const QVector3D& rayOrigin, const QVector3D& rayDirection, const Obstacle& obstacle,
                              float& tEnter, float& tExit);

/**
 * @brief Основная функция для точной проверки линии видимости между двумя точками.
 * Эта функция будет использовать intersectRayPolygonPrism или intersectRayGeneralShape
 * в зависимости от типа препятствия.
 * @param pointA Начальная точка отрезка.
 * @param pointB Конечная точка отрезка.
 * @param allObstacles Список всех препятствий на карте.
 * @return Указатель на первое препятствие, блокирующее линию видимости, или nullptr, если путь свободен.
 */
const Obstacle* getFirstObstacleInPreciseLoS(const QVector3D& pointA, const QVector3D& pointB,
                                             const QList<Obstacle>& allObstacles);

/**
 * @brief Упрощенная версия точной проверки линии видимости.
 * @param pointA Начальная точка отрезка.
 * @param pointB Конечная точка отрезка.
 * @param allObstacles Список всех препятствий на карте.
 * @return true, если между pointA и pointB есть прямая видимость (с учетом точной геометрии препятствий), иначе false.
 */
bool hasPreciseLineOfSight(const QVector3D& pointA, const QVector3D& pointB, const QList<Obstacle>& allObstacles);

}  // namespace LoS
}  // namespace Core
