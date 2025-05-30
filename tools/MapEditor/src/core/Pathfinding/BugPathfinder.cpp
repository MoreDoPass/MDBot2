#include "BugPathfinder.h"
#include <QDebug>  // Для qCInfo, qCWarning, qCDebug
#include <limits>  // Для std::numeric_limits

// Определение категории логирования (должно совпадать с Q_DECLARE_LOGGING_CATEGORY в .h)
Q_LOGGING_CATEGORY(bugPathfinderLog, "core.pathfinding.bug")

namespace Core
{
namespace Pathfinding
{

BugPathfinder::BugPathfinder(QObject* parent)
    : QObject(parent),
      m_currentState(BugPathState::IDLE),
      m_obstacles(nullptr),
      m_waypoints(nullptr),
      m_currentObstacle(nullptr),
      m_distanceToGoalAtHit(0.0f),
      m_minDistanceToGoalOnObstacle(0.0f),
      m_obstacleBoundaryIndex(0),
      m_stepSize(1.0f),                 // Размер шага по умолчанию
      m_obstacleDetectionRadius(0.5f),  // Пока не используется активно, но может пригодиться
      m_goalReachedThreshold(0.5f)      // Порог для достижения цели
{
    qCInfo(bugPathfinderLog) << "BugPathfinder created.";
}

void BugPathfinder::findPath(const QVector3D& startPos, const QVector3D& goalPos, const QList<Obstacle>& obstacles,
                             const QList<Waypoint>& allWaypoints)
{
    reset();
    qCInfo(bugPathfinderLog) << "Finding path from" << startPos << "to" << goalPos;

    m_startPosition = startPos;
    m_currentPosition = startPos;
    m_goalPosition = goalPos;
    m_obstacles = &obstacles;     // Сохраняем указатель
    m_waypoints = &allWaypoints;  // Сохраняем указатель (может быть пустым)

    if (m_currentPosition.distanceToPoint(m_goalPosition) < m_goalReachedThreshold)
    {
        qCInfo(bugPathfinderLog) << "Start position is already at the goal.";
        m_currentState = BugPathState::PATH_FOUND;
        m_currentPath.append(m_currentPosition);
        emit pathFound(m_currentPath);
        return;
    }

    m_currentState = BugPathState::MOVING_TO_GOAL;
    m_currentPath.append(m_currentPosition);  // Начальная точка добавляется в путь
    emit stateChanged(m_currentState);
}

BugPathState BugPathfinder::update()
{
    if (m_currentState == BugPathState::IDLE || m_currentState == BugPathState::PATH_FOUND ||
        m_currentState == BugPathState::PATH_NOT_FOUND)
    {
        return m_currentState;
    }

    // Ограничение на максимальное количество шагов/итераций, чтобы избежать бесконечных циклов
    // TODO: Сделать это более умным или настраиваемым
    const int MAX_ITERATIONS = 10000;
    if (m_currentPath.size() > MAX_ITERATIONS)
    {
        qCWarning(bugPathfinderLog) << "Max iterations reached, path not found.";
        m_currentState = BugPathState::PATH_NOT_FOUND;
        emit pathNotFound();
        emit stateChanged(m_currentState);
        return m_currentState;
    }

    switch (m_currentState)
    {
        case BugPathState::MOVING_TO_GOAL:
            moveToGoal();
            break;
        case BugPathState::FOLLOWING_OBSTACLE:
            followObstacle();
            break;
        case BugPathState::LEAVING_OBSTACLE:
            // Пока это состояние не используется, но если бы использовалось:
            // moveToGoal(); // или специальная логика покидания
            qCWarning(bugPathfinderLog)
                << "LEAVING_OBSTACLE state not fully implemented yet, transitioning to MOVING_TO_GOAL";
            m_currentState = BugPathState::MOVING_TO_GOAL;
            emit stateChanged(m_currentState);
            break;
        default:
            qCWarning(bugPathfinderLog) << "Unhandled state in update():" << static_cast<int>(m_currentState);
            break;
    }

    if (m_currentPosition.distanceToPoint(m_goalPosition) < m_goalReachedThreshold)
    {
        if (m_currentState != BugPathState::PATH_FOUND)  // Чтобы не дублировать сигнал
        {
            qCInfo(bugPathfinderLog) << "Goal reached at" << m_currentPosition;
            m_currentPath.append(m_goalPosition);  // Добавляем саму цель для точности
            m_currentState = BugPathState::PATH_FOUND;
            emit pathFound(m_currentPath);
            emit stateChanged(m_currentState);
        }
    }
    return m_currentState;
}

const QList<QVector3D>& BugPathfinder::getCurrentPath() const
{
    return m_currentPath;
}

QVector3D BugPathfinder::getCurrentPosition() const
{
    return m_currentPosition;
}

void BugPathfinder::reset()
{
    qCInfo(bugPathfinderLog) << "Resetting BugPathfinder state.";
    m_currentState = BugPathState::IDLE;
    m_startPosition = QVector3D();
    m_goalPosition = QVector3D();
    m_currentPosition = QVector3D();
    m_currentPath.clear();
    m_obstacles = nullptr;
    m_waypoints = nullptr;

    m_hitPoint = QVector3D();
    m_currentObstacle = nullptr;
    m_distanceToGoalAtHit = 0.0f;
    m_leavePoint = QVector3D();
    m_minDistanceToGoalOnObstacle = std::numeric_limits<float>::max();
    m_obstacleBoundaryPoints.clear();
    m_obstacleBoundaryIndex = 0;

    // emit stateChanged(m_currentState); // Можно и не сигналить при ресете в IDLE
}

// --- Вспомогательные методы (заглушки или начальная реализация) ---

void BugPathfinder::moveToGoal()
{
    qCDebug(bugPathfinderLog) << "State: MOVING_TO_GOAL. Current pos:" << m_currentPosition;
    QVector3D directionToGoal = (m_goalPosition - m_currentPosition);
    float distanceToGoal = directionToGoal.length();

    if (distanceToGoal < m_goalReachedThreshold)
    {
        // Уже обработается в конце update()
        return;
    }
    directionToGoal.normalize();

    // Проверяем LoS до цели
    const Obstacle* blockingObstacle = nullptr;
    QVector3D potentialHitPoint;
    // Используем distanceToGoal как максимальное расстояние для проверки
    if (findClosestObstacleInLoS(m_currentPosition, m_goalPosition, distanceToGoal, blockingObstacle,
                                 potentialHitPoint))
    {
        qCInfo(bugPathfinderLog) << "Obstacle" << blockingObstacle->id
                                 << "detected in LoS to goal. Switching to FOLLOWING_OBSTACLE. Hit at:"
                                 << potentialHitPoint;
        m_currentObstacle = blockingObstacle;
        m_hitPoint = potentialHitPoint;  // <<--- Устанавливаем корректный m_hitPoint

        m_distanceToGoalAtHit = m_hitPoint.distanceToPoint(m_goalPosition);
        m_minDistanceToGoalOnObstacle = m_distanceToGoalAtHit;

        generateObstacleBoundaryPath(*m_currentObstacle, m_hitPoint);
        if (m_obstacleBoundaryPoints.isEmpty())
        {
            qCWarning(bugPathfinderLog) << "Failed to generate obstacle boundary path for obstacle ID:"
                                        << m_currentObstacle->id << ". Path not found.";
            m_currentState = BugPathState::PATH_NOT_FOUND;
            emit pathNotFound();
        }
        else
        {
            m_currentState = BugPathState::FOLLOWING_OBSTACLE;
            m_obstacleBoundaryIndex = 0;  // Начинаем обход с первой точки границы
        }
        emit stateChanged(m_currentState);
    }
    else
    {
        // Нет препятствий на пути к цели, двигаемся
        QVector3D nextPos = m_currentPosition + directionToGoal * m_stepSize;
        if (m_currentPosition.distanceToPoint(m_goalPosition) < m_stepSize)
        {
            m_currentPosition = m_goalPosition;  // Если близко, просто перемещаемся в цель
        }
        else
        {
            m_currentPosition = nextPos;
        }
        m_currentPath.append(m_currentPosition);
        qCDebug(bugPathfinderLog) << "Moving towards goal. New pos:" << m_currentPosition;
    }
}

void BugPathfinder::followObstacle()
{
    qCDebug(bugPathfinderLog) << "State: FOLLOWING_OBSTACLE. Obstacle ID:"
                              << (m_currentObstacle ? m_currentObstacle->id : -1)
                              << "Boundary index:" << m_obstacleBoundaryIndex << "/" << m_obstacleBoundaryPoints.size();

    if (!m_currentObstacle || m_obstacleBoundaryPoints.isEmpty())
    {
        qCWarning(bugPathfinderLog) << "No current obstacle or boundary points to follow. Switching to MOVING_TO_GOAL.";
        m_currentState = BugPathState::MOVING_TO_GOAL;
        emit stateChanged(m_currentState);
        return;
    }

    // Пытаемся покинуть препятствие
    if (canLeaveObstacle())
    {
        qCInfo(bugPathfinderLog) << "Can leave obstacle. Switching to MOVING_TO_GOAL.";
        // m_leavePoint уже должна быть установлена в canLeaveObstacle или здесь
        // m_currentPosition = m_leavePoint; // Перемещаемся в точку отрыва
        // m_currentPath.append(m_currentPosition); // Добавляем точку отрыва в путь
        m_currentObstacle = nullptr;  // Больше не следим за этим препятствием
        m_obstacleBoundaryPoints.clear();
        m_obstacleBoundaryIndex = 0;
        m_currentState = BugPathState::MOVING_TO_GOAL;
        emit stateChanged(m_currentState);
        return;
    }

    // Движемся к следующей точке на границе препятствия
    if (m_obstacleBoundaryIndex < m_obstacleBoundaryPoints.size())
    {
        QVector3D nextBoundaryPoint = m_obstacleBoundaryPoints[m_obstacleBoundaryIndex];
        // Двигаемся шагами m_stepSize к nextBoundaryPoint
        QVector3D directionToBoundaryNode = (nextBoundaryPoint - m_currentPosition);
        if (directionToBoundaryNode.lengthSquared() < m_stepSize * m_stepSize * 0.25f)
        {  // Если очень близко к узлу границы
            m_currentPosition = nextBoundaryPoint;
            m_obstacleBoundaryIndex++;
        }
        else
        {
            directionToBoundaryNode.normalize();
            m_currentPosition += directionToBoundaryNode * m_stepSize;
        }

        m_currentPath.append(m_currentPosition);
        qCDebug(bugPathfinderLog) << "Following obstacle. New pos:" << m_currentPosition
                                  << ". Next boundary target index:" << m_obstacleBoundaryIndex;

        // Обновляем минимальное расстояние до цели, достигнутое при обходе
        float distToGoal = m_currentPosition.distanceToPoint(m_goalPosition);
        if (distToGoal < m_minDistanceToGoalOnObstacle)
        {
            m_minDistanceToGoalOnObstacle = distToGoal;
            // m_leavePoint = m_currentPosition; // Потенциальная точка отрыва (для Bug1)
        }
        // Если обошли все точки, а покинуть не смогли (например, цель внутри препятствия или замкнутый цикл)
        if (m_obstacleBoundaryIndex >= m_obstacleBoundaryPoints.size())
        {
            // Это может означать, что мы вернулись в начало обхода или что-то пошло не так.
            // Для Bug2: если мы вернулись к m_hitPoint (или точке на M-Line ближе всего к m_hitPoint)
            // и m_minDistanceToGoalOnObstacle не улучшилось, то путь не найден.
            // Пока простая заглушка:
            qCWarning(bugPathfinderLog) << "Completed boundary trace. If still cannot leave, path might be impossible.";
            // Для простоты, если мы обошли все точки и не вышли, считаем путь невозможным
            // (это не совсем корректно для всех Bug алгоритмов, но для начала)
            // В более сложной логике, мы бы могли попробовать обойти еще раз или проверить условия тупика.
            // Если m_currentPosition очень близко к m_hitPoint и m_minDistanceToGoalOnObstacle не сильно лучше
            // m_distanceToGoalAtHit, то это может быть признаком невозможности.

            // Если мы действительно вернулись к точке начала обхода (m_hitPoint)
            // и не смогли уйти раньше, и при этом m_minDistanceToGoalOnObstacle не меньше,
            // чем m_distanceToGoalAtHit (т.е. не нашли лучшей точки для ухода), то путь не найден.
            // Это упрощенная проверка.
            if (m_currentPosition.distanceToPoint(m_hitPoint) < m_stepSize &&
                m_minDistanceToGoalOnObstacle >= m_distanceToGoalAtHit)
            {
                qCWarning(bugPathfinderLog)
                    << "Returned to hit point without finding a better leave point. Path not found.";
                m_currentState = BugPathState::PATH_NOT_FOUND;
                emit pathNotFound();
                emit stateChanged(m_currentState);
            }
            else
            {
                // Если мы просто закончили список точек, но это не hitPoint,
                // может быть ошибка в generateObstacleBoundaryPath или препятствие очень маленькое.
                // Попробуем снова перейти к MOVING_TO_GOAL, чтобы переоценить обстановку.
                // Это может привести к зацикливанию, если generateObstacleBoundaryPath всегда дает тот же короткий
                // путь.
                qCWarning(bugPathfinderLog) << "Finished boundary points, but not at hitPoint or condition for "
                                               "unreachability not met. Trying to move to goal again.";
                m_currentObstacle = nullptr;
                m_obstacleBoundaryPoints.clear();
                m_obstacleBoundaryIndex = 0;
                m_currentState = BugPathState::MOVING_TO_GOAL;
                emit stateChanged(m_currentState);
            }
        }
    }
    else
    {
        // Должны были выйти раньше или определить невозможность
        qCWarning(bugPathfinderLog)
            << "Boundary index out of bounds, but still in FOLLOWING_OBSTACLE. This shouldn't happen.";
        m_currentState = BugPathState::PATH_NOT_FOUND;  // Безопасный выход
        emit pathNotFound();
        emit stateChanged(m_currentState);
    }
}

bool BugPathfinder::canLeaveObstacle()
{
    if (!m_currentObstacle) return true;  // Если нет текущего препятствия, то можно "уходить"

    // Условие 1: Текущая позиция на M-Line?
    if (!isPointOnMLine(m_currentPosition))
    {
        return false;  // Не на M-Line, продолжаем обход
    }
    // qCDebug(bugPathfinderLog) << "Point" << m_currentPosition << "is on M-Line.";

    // Условие 2: Есть ли прямая видимость до цели?
    if (!Core::LoS::hasLineOfSightAABB(m_currentPosition, m_goalPosition, *m_obstacles))
    {
        // qCDebug(bugPathfinderLog) << "On M-Line, but no LoS to goal from" << m_currentPosition;
        return false;  // LoS заблокирован, продолжаем обход
    }
    // qCDebug(bugPathfinderLog) << "On M-Line, LoS to goal is clear from" << m_currentPosition;

    // Условие 3: Текущее расстояние до цели меньше, чем в точке столкновения?
    float currentDistanceToGoal = m_currentPosition.distanceToPoint(m_goalPosition);
    if (currentDistanceToGoal >=
        m_distanceToGoalAtHit - 1e-5f)  // Добавим небольшой допуск, чтобы избежать проблем с плавающей точкой
    {
        // qCDebug(bugPathfinderLog) << "On M-Line, LoS clear, but currentDist (" << currentDistanceToGoal
        //                          << ") not significantly less than distAtHit (" << m_distanceToGoalAtHit << ")";
        return false;  // Не стали ближе к цели (или почти не стали), продолжаем обход
    }

    // Условие 4: Мы не пытаемся покинуть препятствие в той же точке, где столкнулись (или очень близко к ней)?
    // Это предотвращает немедленный выход, если m_hitPoint случайно оказалась на M-Line и имела LoS.
    // Порог m_stepSize может быть слишком большим, если шаги мелкие. Может, лучше сравнивать с меньшим порогом,
    // или убедиться, что мы сделали хотя бы один шаг по m_obstacleBoundaryPoints.
    // Пока оставим m_stepSize.
    if (m_currentPosition.distanceToPoint(m_hitPoint) < m_stepSize * 0.5f &&
        m_obstacleBoundaryIndex < 1)  // Если мы очень близко к hitPoint и еще не начали обход
    {
        // qCDebug(bugPathfinderLog) << "On M-Line, LoS clear, closer to goal, but too close to hitPoint and haven't
        // moved along boundary yet.";
        return false;
    }

    qCDebug(bugPathfinderLog) << "CAN LEAVE OBSTACLE: On M-Line, LoS to goal, currentDist (" << currentDistanceToGoal
                              << ") < distAtHit (" << m_distanceToGoalAtHit << ")";
    m_leavePoint =
        m_currentPosition;  // Запоминаем точку отрыва (хотя для текущей логики она не используется для решения)
    return true;
}

bool BugPathfinder::findClosestObstacleInLoS(const QVector3D& from, const QVector3D& to, float maxDist,
                                             const Obstacle*& foundObstacle, QVector3D& hitPoint)
{
    if (!m_obstacles)
    {
        foundObstacle = nullptr;
        return false;
    }

    QVector3D rayDirection = to - from;
    float distanceToOriginalTarget = rayDirection.length();
    if (distanceToOriginalTarget < 1e-6f)
    {
        foundObstacle = nullptr;
        return false;  // Точки совпадают
    }
    rayDirection.normalize();

    // Используем новую функцию из Core::LoS
    // maxDist здесь - это максимальная длина луча, которую мы хотим проверить.
    // Это может быть distanceToOriginalTarget, если мы проверяем только до цели,
    // или какое-то другое значение, если мы зондируем на определенную дальность.
    // В moveToGoal мы передавали distanceToGoal, так что это логично.
    float actualHitDistance;  // Эта переменная будет заполнена функцией findClosestAABBIntersection

    // Важно: maxDist, передаваемый в findClosestAABBIntersection, должен быть фактическим расстоянием,
    // на котором мы ищем пересечение, а не просто максимальным значением float.
    // Если мы ищем пересечение на пути к 'to', то maxDist должен быть distanceToOriginalTarget.
    if (Core::LoS::findClosestAABBIntersection(from, rayDirection, *m_obstacles, distanceToOriginalTarget,
                                               foundObstacle, hitPoint, actualHitDistance))
    {
        // Пересечение найдено функцией LoS. foundObstacle и hitPoint уже установлены.
        // actualHitDistance содержит расстояние до точки пересечения.
        // qCDebug(bugPathfinderLog) << "BugPathfinder::findClosestObstacleInLoS: Found intersection with"
        //                           << foundObstacle->id << "at" << hitPoint << "dist:" << actualHitDistance;
        return true;
    }

    foundObstacle = nullptr;
    return false;
}

void BugPathfinder::generateObstacleBoundaryPath(const Obstacle& obs, const QVector3D& entryPoint)
{
    m_obstacleBoundaryPoints.clear();
    m_obstacleBoundaryIndex = 0;
    qCDebug(bugPathfinderLog) << "Generating boundary path for obstacle ID:" << obs.id
                              << "near entry point:" << entryPoint;

    float agentY = entryPoint.y();  // Используем Y координату точки входа для всего пути обхода

    QList<QVector3D> contourPoints;  // Временный список для вершин контура

    if (!obs.shapeVertices.isEmpty())
    {
        int closestVertexIndex = -1;
        float minDistanceSq = std::numeric_limits<float>::max();
        for (int i = 0; i < obs.shapeVertices.size(); ++i)
        {
            // Сравниваем по XZ для нахождения ближайшей вершины на плоскости агента
            QVector2D v_proj(obs.shapeVertices[i].x(), obs.shapeVertices[i].z());
            QVector2D entry_proj(entryPoint.x(), entryPoint.z());
            float distSq = (v_proj - entry_proj).lengthSquared();
            if (distSq < minDistanceSq)
            {
                minDistanceSq = distSq;
                closestVertexIndex = i;
            }
        }

        if (closestVertexIndex != -1)
        {
            int num_vertices = obs.shapeVertices.size();
            for (int i = 0; i < num_vertices; ++i)
            {
                int current_idx = (closestVertexIndex + i) % num_vertices;
                const QVector3D& original_vertex = obs.shapeVertices[current_idx];
                contourPoints.append(QVector3D(original_vertex.x(), agentY, original_vertex.z()));
            }
        }
        else
        {
            qCWarning(bugPathfinderLog) << "Obstacle" << obs.id
                                        << "has shapeVertices but could not determine starting point for boundary.";
        }
    }
    else if (!obs.baseVertices.isEmpty() && obs.obstacleHeight > 0)
    {
        int closestVertexIndex = -1;
        float minDistanceSq = std::numeric_limits<float>::max();
        for (int i = 0; i < obs.baseVertices.size(); ++i)
        {
            QVector2D v_proj(obs.baseVertices[i].x(), obs.baseVertices[i].z());
            QVector2D entry_proj(entryPoint.x(), entryPoint.z());
            float distSq = (v_proj - entry_proj).lengthSquared();
            if (distSq < minDistanceSq)
            {
                minDistanceSq = distSq;
                closestVertexIndex = i;
            }
        }
        if (closestVertexIndex != -1)
        {
            int num_vertices = obs.baseVertices.size();
            for (int i = 0; i < num_vertices; ++i)
            {
                int current_idx = (closestVertexIndex + i) % num_vertices;
                const QVector3D& base_vertex = obs.baseVertices[current_idx];
                contourPoints.append(QVector3D(base_vertex.x(), agentY, base_vertex.z()));
            }
        }
        else
        {
            qCWarning(bugPathfinderLog) << "Obstacle" << obs.id
                                        << "has baseVertices but could not determine starting point for boundary.";
        }
    }
    else  // Фоллбэк на AABB
    {
        qCWarning(bugPathfinderLog) << "Obstacle ID:" << obs.id
                                    << "has no shape or base vertices for precise boundary. Using AABB (crude).";
        contourPoints.append(QVector3D(obs.minCorner.x(), agentY, obs.minCorner.z()));
        contourPoints.append(QVector3D(obs.maxCorner.x(), agentY, obs.minCorner.z()));
        contourPoints.append(QVector3D(obs.maxCorner.x(), agentY, obs.maxCorner.z()));
        contourPoints.append(QVector3D(obs.minCorner.x(), agentY, obs.maxCorner.z()));
    }

    // Теперь интегрируем entryPoint (m_hitPoint) в m_obstacleBoundaryPoints
    if (contourPoints.isEmpty())
    {
        qCWarning(bugPathfinderLog) << "Failed to generate any contour points for obstacle ID:" << obs.id
                                    << "Cannot create boundary path.";
        return;  // Нечего делать, если контур пуст
    }

    // Проверяем, не совпадает ли entryPoint (m_hitPoint) с первой точкой контура
    // Допуск для сравнения с плавающей точкой
    const float epsilon = 1e-4f;
    bool entryPointIsFirstContourPoint = false;
    if ((entryPoint - contourPoints.first()).lengthSquared() < epsilon * epsilon)
    {
        entryPointIsFirstContourPoint = true;
    }

    if (entryPointIsFirstContourPoint)
    {
        // entryPoint уже первая точка, просто используем contourPoints
        m_obstacleBoundaryPoints = contourPoints;
    }
    else
    {
        // entryPoint не первая точка. Вставляем ее в начало,
        // а затем остальные точки контура.
        // Это простой способ гарантировать, что обход начнется с entryPoint.
        // Более сложная логика могла бы найти ближайший сегмент контура к entryPoint
        // и вставить entryPoint между вершинами этого сегмента, но это сложнее.
        m_obstacleBoundaryPoints.append(entryPoint);
        m_obstacleBoundaryPoints.append(contourPoints);
    }

    // Опционально: Убедиться, что путь замкнут, если он должен быть (т.е. последняя точка ведет к первой)
    // Для Bug-алгоритма важно, чтобы был четкий путь вдоль границы. Если entryPoint была не вершиной,
    // а точкой на ребре, то наш текущий m_obstacleBoundaryPoints может выглядеть так: [entryPoint, v1, v2, ..., vn].
    // Если v1 была исходно ближайшей вершиной, это может быть нормально.
    // Если мы хотим строго замкнуть путь так, чтобы последняя точка вела к m_obstacleBoundaryPoints.first(),
    // то это нужно проверить. Но для Bug-алгоритма, который итерирует по списку, это может быть не критично,
    // т.к. он остановится, когда m_obstacleBoundaryIndex выйдет за пределы.

    if (!m_obstacleBoundaryPoints.isEmpty())
    {
        qCDebug(bugPathfinderLog) << "Generated" << m_obstacleBoundaryPoints.size()
                                  << "boundary points. First point:" << m_obstacleBoundaryPoints.first();
    }
    else
    {
        qCWarning(bugPathfinderLog) << "Failed to generate any boundary points for obstacle ID:" << obs.id;
    }
}

bool BugPathfinder::isPointOnMLine(const QVector3D& point) const
{
    // M-Line - это отрезок между m_startPosition и m_goalPosition.
    // Для простоты будем проверять на 2D-плоскости XZ.
    // Точность сравнения для чисел с плавающей запятой.
    constexpr float epsilon = 1e-4f;

    QVector2D p(point.x(), point.z());
    QVector2D start(m_startPosition.x(), m_startPosition.z());
    QVector2D goal(m_goalPosition.x(), m_goalPosition.z());

    // 1. Проверка коллинеарности (используя площадь треугольника или псевдо-скалярное произведение)
    // (p.x - start.x) * (goal.y - start.y) - (p.y - start.y) * (goal.x - start.x)
    // Если это значение близко к нулю, точки коллинеарны.
    float crossProduct = (p.x() - start.x()) * (goal.y() - start.y()) - (p.y() - start.y()) * (goal.x() - start.x());

    if (std::abs(crossProduct) > epsilon)  // Увеличим допуск, если нужно, для более грубой проверки
    {
        return false;  // Не коллинеарны
    }

    // 2. Проверка, что точка p лежит на отрезке [start, goal]
    // Это можно сделать, проверив, что скалярное произведение (p - start) * (p - goal) <= 0
    // Это означает, что угол между векторами (p - start) и (p - goal) >= 90 градусов,
    // что возможно, только если p между start и goal (или совпадает с одним из них).
    QVector2D vec_sp = p - start;
    QVector2D vec_pg = p - goal;
    float dotProduct = QVector2D::dotProduct(vec_sp, vec_pg);

    if (dotProduct > epsilon)  // Если > 0, то p вне отрезка (но на прямой)
    {
        return false;
    }

    // Дополнительная проверка: убедимся, что точка не выходит за bounding box отрезка.
    // Это помогает с погрешностями, когда точка очень близко к концу отрезка, но формально вне его по dotProduct.
    if (p.x() < qMin(start.x(), goal.x()) - epsilon || p.x() > qMax(start.x(), goal.x()) + epsilon ||
        p.y() < qMin(start.y(), goal.y()) - epsilon || p.y() > qMax(start.y(), goal.y()) + epsilon)
    {
        // qCDebug(bugPathfinderLog) << "Point" << p << "is collinear but outside M-Line segment bbox" << start << "-"
        // << goal;
        return false;
    }

    return true;
}

}  // namespace Pathfinding
}  // namespace Core
