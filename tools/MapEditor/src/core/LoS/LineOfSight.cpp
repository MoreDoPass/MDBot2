#include "LineOfSight.h"
#include <QDebug>  // Для qCDebug, qCWarning
#include <limits>  // Для std::numeric_limits
#include <cmath>   // Для std::abs, std::floor и др.

// Определение категории логирования (должно совпадать с Q_DECLARE_LOGGING_CATEGORY в .h)
Q_LOGGING_CATEGORY(losLog, "core.los")

namespace Core
{
namespace LoS
{

bool intersectRayAABB(const QVector3D& rayOrigin, const QVector3D& rayDirection, const Obstacle& obstacle,
                      float& tIntersectionMin, float& tIntersectionMax)
{
    // qCDebug(losLog) << QString("[LoS_Debug] intersectRayAABB for Obstacle ID: %1 (%2) Origin: (%3, %4, %5) Dir: (%6,
    // %7, %8)")
    //                            .arg(obstacle.id).arg(obstacle.name)
    //                            .arg(rayOrigin.x()).arg(rayOrigin.y()).arg(rayOrigin.z())
    //                            .arg(rayDirection.x()).arg(rayDirection.y()).arg(rayDirection.z());
    // qCDebug(losLog) << QString("[LoS_Debug] Obstacle bounds: Min(%1, %2, %3) Max(%4, %5, %6)")
    //                            .arg(obstacle.minCorner.x()).arg(obstacle.minCorner.y()).arg(obstacle.minCorner.z())
    //                            .arg(obstacle.maxCorner.x()).arg(obstacle.maxCorner.y()).arg(obstacle.maxCorner.z());

    float currentTMin = std::numeric_limits<float>::lowest();
    float currentTMax = std::numeric_limits<float>::max();

    const QVector3D& minBounds = obstacle.minCorner;
    const QVector3D& maxBounds = obstacle.maxCorner;

    for (int i = 0; i < 3; ++i)
    {  // Iterate over x, y, z axes
        if (std::abs(rayDirection[i]) < 1e-6f)
        {  // Ray is parallel to the slab planes for this axis
            if (rayOrigin[i] < minBounds[i] || rayOrigin[i] > maxBounds[i])
            {
                // qCDebug(losLog) << "[LoS_Debug] intersectRayAABB: Parallel and outside slab on axis" << i << "->
                // returning false";
                return false;  // Parallel and outside slab, no intersection
            }
            // qCDebug(losLog) << "[LoS_Debug] intersectRayAABB: Parallel and inside slab on axis" << i;
        }
        else
        {
            float invD = 1.0f / rayDirection[i];
            float t0 = (minBounds[i] - rayOrigin[i]) * invD;
            float t1 = (maxBounds[i] - rayOrigin[i]) * invD;

            if (invD < 0.0f)
            {  // Ensure t0 is intersection with near plane, t1 with far plane
                std::swap(t0, t1);
            }
            currentTMin = std::max(currentTMin, t0);
            currentTMax = std::min(currentTMax, t1);

            if (currentTMax <= currentTMin)
            {  // Intersection interval is empty or a single point
                // qCDebug(losLog) << "[LoS_Debug] intersectRayAABB: No intersection (tMax <= tMin). tMin=" <<
                // currentTMin << "tMax=" << currentTMax << "on axis" << i << "-> returning false";
                return false;
            }
        }
    }
    tIntersectionMin = currentTMin;
    tIntersectionMax = currentTMax;
    // qCDebug(losLog) << "[LoS_Debug] intersectRayAABB: Intersection FOUND. tMin=" << tIntersectionMin << "tMax=" <<
    // tIntersectionMax << "-> returning true";
    return true;
}

// Реализация взята из MainWindow::hasLineOfSight
bool hasLineOfSightAABB(const QVector3D& pointA, const QVector3D& pointB, const QList<Obstacle>& allObstacles)
{
    QVector3D rayDirection = pointB - pointA;
    float distanceToTarget = rayDirection.length();
    // qCDebug(losLog) << QString("[LoS_Debug] hasLineOfSightAABB PointA: (%1, %2, %3) PointB: (%4, %5, %6) Dist: %7")
    //                        .arg(pointA.x()).arg(pointA.y()).arg(pointA.z())
    //                        .arg(pointB.x()).arg(pointB.y()).arg(pointB.z()).arg(distanceToTarget);

    if (distanceToTarget < 0.001f) return true;  // Точки совпадают
    rayDirection.normalize();

    for (const Obstacle& obs : allObstacles)
    {
        float tIntersectionEnter, tIntersectionExit;
        if (intersectRayAABB(pointA, rayDirection, obs, tIntersectionEnter, tIntersectionExit))
        {
            // qCDebug(losLog) << QString("[LoS_Debug] hasLineOfSightAABB: Ray INTERSECTED obs %1 (%2). tEnter=%3,
            // tExit=%4, distToTarget=%5")
            //                        .arg(obs.id).arg(obs.name).arg(tIntersectionEnter).arg(tIntersectionExit).arg(distanceToTarget);
            if (tIntersectionEnter < distanceToTarget && tIntersectionEnter >= 0.0f &&
                tIntersectionEnter < tIntersectionExit)
            {
                // qCDebug(losLog) << "[LoS_Debug] hasLineOfSightAABB: Obstacle is BETWEEN A and B. LoS blocked. ->
                // returning false";
                return false;  // LoS заблокирован
            }
        }
    }
    return true;  // Нет препятствий на пути
}

bool findClosestAABBIntersection(const QVector3D& rayOrigin, const QVector3D& rayDirection,
                                 const QList<Obstacle>& allObstacles, float maxDistance, const Obstacle*& hitObstacle,
                                 QVector3D& hitPoint, float& hitDistance)
{
    hitObstacle = nullptr;
    hitDistance = std::numeric_limits<float>::max();
    bool foundIntersection = false;

    for (const Obstacle& obs : allObstacles)
    {
        float tIntersectionEnter, tIntersectionExit;
        if (intersectRayAABB(rayOrigin, rayDirection, obs, tIntersectionEnter, tIntersectionExit))
        {
            // Пересечение должно быть перед нами (tIntersectionEnter >= 0), в пределах maxDistance,
            // и точка входа должна быть раньше точки выхода (на случай если начало луча внутри AABB).
            if (tIntersectionEnter >= -1e-6f && tIntersectionEnter < maxDistance &&
                tIntersectionEnter < tIntersectionExit)
            {
                if (tIntersectionEnter < hitDistance)  // Нашли более близкое пересечение
                {
                    hitDistance = tIntersectionEnter;
                    hitObstacle = &obs;
                    foundIntersection = true;
                }
            }
        }
    }

    if (foundIntersection)
    {
        hitPoint = rayOrigin + rayDirection * hitDistance;
        // qCDebug(losLog) << "findClosestAABBIntersection: Found intersection with Obstacle ID:" << hitObstacle->id
        //                 << "at distance:" << hitDistance << "Point:" << hitPoint;
    }
    return foundIntersection;
}

// --- Реализации для точной проверки (пока заглушки) ---
bool intersectRayPolygonPrism(const QVector3D& rayOrigin, const QVector3D& rayDirection, const Obstacle& obstacle,
                              float& tEnter, float& tExit)
{
    Q_UNUSED(rayOrigin);
    Q_UNUSED(rayDirection);
    Q_UNUSED(obstacle);
    Q_UNUSED(tEnter);
    Q_UNUSED(tExit);
    qCWarning(losLog) << "intersectRayPolygonPrism not implemented yet.";
    return false;  // Заглушка
}

bool intersectRayGeneralShape(const QVector3D& rayOrigin, const QVector3D& rayDirection, const Obstacle& obstacle,
                              float& tEnter, float& tExit)
{
    Q_UNUSED(rayOrigin);
    Q_UNUSED(rayDirection);
    Q_UNUSED(obstacle);
    Q_UNUSED(tEnter);
    Q_UNUSED(tExit);
    qCWarning(losLog) << "intersectRayGeneralShape not implemented yet.";
    // Для начала, можно попробовать использовать baseVertices, если shapeVertices пусты
    if (!obstacle.shapeVertices.isEmpty())
    {
        // TODO: Реализовать пересечение с произвольной формой (мешем)
        // Это сложная задача, требующая пересечения луча с треугольниками.
    }
    else if (!obstacle.baseVertices.isEmpty() && obstacle.obstacleHeight > 0.0f)
    {
        // Можно вызвать intersectRayPolygonPrism, если он будет реализован
        return intersectRayPolygonPrism(rayOrigin, rayDirection, obstacle, tEnter, tExit);
    }
    return false;  // Заглушка
}

const Obstacle* getFirstObstacleInPreciseLoS(const QVector3D& pointA, const QVector3D& pointB,
                                             const QList<Obstacle>& allObstacles)
{
    QVector3D rayDirection = pointB - pointA;
    float distanceToTarget = rayDirection.length();

    if (distanceToTarget < 0.001f) return nullptr;  // Точки совпадают, видимость есть
    rayDirection.normalize();

    const Obstacle* closestBlockingObstacle = nullptr;
    float minBlockingDistance = std::numeric_limits<float>::max();

    for (const Obstacle& obs : allObstacles)
    {
        float tEnter, tExit;
        bool intersects = false;

        // Выбираем метод пересечения в зависимости от данных препятствия
        if (!obs.shapeVertices.isEmpty())
        {
            // Предполагаем, что shapeVertices - это набор вершин для произвольной формы
            // или контура полигона, который будет использоваться в intersectRayGeneralShape
            intersects = intersectRayGeneralShape(pointA, rayDirection, obs, tEnter, tExit);
        }
        // Если shapeVertices пуст, но есть baseVertices (старый формат призмы)
        // или если intersectRayGeneralShape должен был бы это обработать, но не смог
        else if (!obs.baseVertices.isEmpty() && obs.obstacleHeight > 0.0f)
        {
            intersects = intersectRayPolygonPrism(pointA, rayDirection, obs, tEnter, tExit);
        }
        // Если ничего из вышеперечисленного, но есть min/max углы (AABB)
        // Это будет запасным вариантом, если точные методы не реализованы или неприменимы
        // Но для *Precise* LoS мы хотим избегать AABB, если возможно.
        // Пока что, если нет точных данных, не будем считать пересечением по AABB здесь.
        // else if (!obs.minCorner.isNull() && !obs.maxCorner.isNull()) {
        //     intersects = intersectRayAABB(pointA, rayDirection, obs, tEnter, tExit);
        // }

        if (intersects)
        {
            if (tEnter < distanceToTarget && tEnter >= -1e-6f && tEnter < tExit)
            {  // tEnter может быть очень маленьким отрицательным из-за погрешностей
                if (tEnter < minBlockingDistance)
                {
                    minBlockingDistance = tEnter;
                    closestBlockingObstacle = &obs;
                }
            }
        }
    }
    if (closestBlockingObstacle)
    {
        // qCDebug(losLog) << "Precise LoS blocked by obstacle ID:" << closestBlockingObstacle->id;
    }
    return closestBlockingObstacle;
}

bool hasPreciseLineOfSight(const QVector3D& pointA, const QVector3D& pointB, const QList<Obstacle>& allObstacles)
{
    return getFirstObstacleInPreciseLoS(pointA, pointB, allObstacles) == nullptr;
}

}  // namespace LoS
}  // namespace Core
