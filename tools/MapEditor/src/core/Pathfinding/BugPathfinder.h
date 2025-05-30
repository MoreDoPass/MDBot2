#pragma once

#include <QVector3D>
#include <QList>
#include <QObject>  // Для Q_OBJECT, если будут сигналы/слоты
#include <QLoggingCategory>

#include "core/MapData/MapData.h"  // Для Obstacle и Waypoint (если нужны)
#include "core/LoS/LineOfSight.h"  // Для проверки линии видимости

Q_DECLARE_LOGGING_CATEGORY(bugPathfinderLog)

namespace Core
{
namespace Pathfinding
{

/**
 * @brief Состояния алгоритма Bug.
 */
enum class BugPathState
{
    MOVING_TO_GOAL,      // Движение напрямую к цели
    FOLLOWING_OBSTACLE,  // Движение вдоль границы препятствия
    LEAVING_OBSTACLE,    // (Опционально) Состояние для решения, когда покинуть препятствие
    PATH_NOT_FOUND,      // Путь не может быть найден
    PATH_FOUND,          // Путь успешно найден
    IDLE                 // Ожидание новой задачи
};

/**
 * @brief Класс, реализующий один из вариантов алгоритма Bug (например, Bug2) для обхода препятствий.
 * Предполагает, что у нас есть информация о препятствиях (например, AABB или более точная геометрия)
 * и возможность проверять линию видимости (LoS).
 */
class BugPathfinder : public QObject
{
    Q_OBJECT
   public:
    explicit BugPathfinder(QObject* parent = nullptr);

    /**
     * @brief Начинает поиск пути от startPos к goalPos, используя предоставленные препятствия.
     * @param startPos Начальная позиция.
     * @param goalPos Целевая позиция.
     * @param obstacles Список препятствий на карте.
     * @param allWaypoints (Опционально) Список всех вейпоинтов, если Bug-алгоритм будет пытаться
     *                     выйти на существующий вейпоинт после обхода препятствия.
     */
    void findPath(const QVector3D& startPos, const QVector3D& goalPos, const QList<Obstacle>& obstacles,
                  const QList<Waypoint>& allWaypoints = {});

    /**
     * @brief Выполняет один шаг/итерацию алгоритма.
     * Вызывается периодически (например, таймером) для продвижения по пути.
     * @return Текущее состояние алгоритма.
     */
    BugPathState update();

    /**
     * @brief Возвращает текущий рассчитанный путь (список точек).
     * Может быть пустым, если путь еще не найден или не может быть найден.
     */
    const QList<QVector3D>& getCurrentPath() const;

    /**
     * @brief Возвращает текущую позицию "агента" (бота), следующего по пути.
     */
    QVector3D getCurrentPosition() const;

    /**
     * @brief Сбрасывает состояние алгоритма для нового поиска.
     */
    void reset();

    BugPathState getCurrentState() const
    {
        return m_currentState;
    }

    // Вспомогательная функция для проверки M-Line
    bool isPointOnMLine(const QVector3D& point) const;

    // Для доступа извне, если нужно будет (например, для отладки)
    const QVector3D& getHitPoint() const
    {
        return m_hitPoint;
    }
    const QVector3D& getStartPosition() const
    {
        return m_startPosition;
    }
    const QVector3D& getGoalPosition() const
    {
        return m_goalPosition;
    }

   signals:
    void pathFound(const QList<QVector3D>& path);
    void pathNotFound();
    void stateChanged(BugPathState newState);

   private:
    // Внутренние переменные состояния
    BugPathState m_currentState;
    QVector3D m_startPosition;                     // Исходная начальная точка
    QVector3D m_goalPosition;                      // Целевая точка
    QVector3D m_currentPosition;                   // Текущее положение "агента"
    QList<QVector3D> m_currentPath;                // Рассчитанный путь (последовательность точек)
    const QList<Obstacle>* m_obstacles = nullptr;  // Указатель на препятствия (не владеет)
    const QList<Waypoint>* m_waypoints = nullptr;  // Указатель на вейпоинты (не владеет)

    // Переменные для Bug2
    QVector3D m_hitPoint;                         // Точка, где столкнулись с препятствием
    const Obstacle* m_currentObstacle = nullptr;  // Препятствие, которое обходим
    float m_distanceToGoalAtHit;                  // Расстояние до цели в момент столкновения
    QVector3D m_leavePoint;                       // Кандидат на точку покидания препятствия
    float m_minDistanceToGoalOnObstacle;          // Минимальное расстояние до цели, достигнутое при обходе
    QList<QVector3D> m_obstacleBoundaryPoints;    // Точки, составляющие путь обхода препятствия
    int m_obstacleBoundaryIndex;                  // Индекс текущей точки на границе препятствия

    // Параметры
    float m_stepSize = 1.0f;                 // Размер шага при движении
    float m_obstacleDetectionRadius = 0.5f;  // Радиус "тела" агента для детекции столкновений
    float m_goalReachedThreshold = 0.5f;     // Порог для определения достижения цели

    // Вспомогательные методы
    void moveToGoal();
    void followObstacle();
    bool canLeaveObstacle();
    bool findClosestObstacleInLoS(const QVector3D& from, const QVector3D& to, float maxDist,
                                  const Obstacle*& foundObstacle, QVector3D& hitPoint);
    void generateObstacleBoundaryPath(const Obstacle& obs, const QVector3D& entryPoint);
};

}  // namespace Pathfinding
}  // namespace Core
