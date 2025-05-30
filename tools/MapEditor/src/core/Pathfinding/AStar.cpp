#include "AStar.h"
#include <QElapsedTimer>  // Для отладки времени выполнения
#include <QDebug>         // Для qCInfo, qCWarning, qCDebug

// Определение категории логирования
Q_LOGGING_CATEGORY(aStarLog, "core.pathfinding.astar")

namespace Core
{
namespace Pathfinding
{

// Реализация взята из MainWindow::heuristic
double heuristic(const Waypoint& a, const Waypoint& b)
{
    return a.coordinates.distanceToPoint(b.coordinates);
}

// Реализация взята из MainWindow::aStarSearch
QList<int> findPathAStar(const MapData& mapData, int startWaypointId, int goalWaypointId)
{
    QElapsedTimer timer;
    timer.start();

    QHash<int, double> gScore;  // Стоимость пути от начала до точки
    QHash<int, double> fScore;  // gScore + эвристика до цели
    QHash<int, int> cameFrom;   // Предыдущая точка на пути к текущей

    // Используем std::priority_queue для openSet
    using PQueuePair = std::pair<double, int>;
    std::priority_queue<PQueuePair, std::vector<PQueuePair>, std::greater<PQueuePair>> openSetQueue;

    // QHash для быстрой проверки наличия в openSet (имитирует проверку в std::set или QSet)
    // Это нужно, чтобы избежать дубликатов в priority_queue или эффективно обновлять приоритеты
    // Стандартная std::priority_queue не поддерживает прямое обновление приоритетов.
    // Один из способов обойти это - добавлять элемент с новым, лучшим приоритетом,
    // а при извлечении проверять, не был ли он уже обработан (через closedSet).
    // Или использовать QSet<int> openSetTrack для проверки, прежде чем добавлять в очередь.
    QHash<int, bool> openSetTrack;
    QHash<int, bool> closedSet;  // Для отслеживания уже обработанных узлов

    const Waypoint* startNode = mapData.findWaypointById(startWaypointId);
    const Waypoint* goalNode = mapData.findWaypointById(goalWaypointId);

    if (!startNode)
    {
        qCWarning(aStarLog) << "A* Search: Start node ID" << startWaypointId << "not found.";
        return {};
    }
    if (!goalNode)
    {
        qCWarning(aStarLog) << "A* Search: Goal node ID" << goalWaypointId << "not found.";
        return {};
    }

    gScore[startWaypointId] = 0;
    fScore[startWaypointId] = heuristic(*startNode, *goalNode);
    openSetQueue.push({fScore[startWaypointId], startWaypointId});
    openSetTrack[startWaypointId] = true;

    qCInfo(aStarLog) << "A* Search: Starting search from" << startWaypointId << "to" << goalWaypointId;
    int iterations = 0;

    while (!openSetQueue.empty())
    {
        iterations++;
        int currentId = openSetQueue.top().second;
        openSetQueue.pop();

        // Если узел уже в closedSet и мы его извлекли (из-за дубликата в PQueue с худшим fScore), пропускаем
        if (closedSet.contains(currentId))
        {
            continue;
        }

        openSetTrack.remove(currentId);  // Удаляем из трекера, так как извлекли из "активного" openSet
        closedSet[currentId] = true;     // Помечаем как обработанный

        if (currentId == goalWaypointId)
        {
            qCInfo(aStarLog) << "A* Search: Goal reached! Path found in" << timer.elapsed() << "ms and" << iterations
                             << "iterations.";
            QList<int> path;
            int temp = currentId;
            // Восстанавливаем путь, идя обратно от цели к старту по cameFrom
            path.prepend(temp);  // Добавляем goalId
            while (cameFrom.contains(temp))
            {
                temp = cameFrom[temp];
                path.prepend(temp);
            }
            // Если startId не был добавлен (например, startId == goalId), убедимся, что он есть, если путь не пуст
            // В текущей логике восстановления, если startId == goalId, path будет {goalId}.
            // Если startId != goalId, но startId == cameFrom.value(path.first()), то он уже будет в path.
            // Цикл while (cameFrom.contains(temp)) остановится, когда temp станет startId (т.к. startId не имеет
            // cameFrom) Таким образом, startId уже будет в path.prepend(temp) на последней итерации перед выходом из
            // while.
            return path;
        }

        const Waypoint* currentNode = mapData.findWaypointById(currentId);
        if (!currentNode) continue;  // Должно быть найдено, если ID корректный

        for (int neighborId : currentNode->connectedWaypointIds)
        {
            if (closedSet.contains(neighborId))
            {
                continue;  // Уже обработан и найден лучший путь к нему
            }

            const Waypoint* neighborNode = mapData.findWaypointById(neighborId);
            if (!neighborNode) continue;

            // Стоимость ребра = расстояние между точками
            double tentative_gScore =
                gScore.value(currentId) + currentNode->coordinates.distanceToPoint(neighborNode->coordinates);

            if (tentative_gScore < gScore.value(neighborId, std::numeric_limits<double>::max()))
            {
                cameFrom[neighborId] = currentId;
                gScore[neighborId] = tentative_gScore;
                fScore[neighborId] = tentative_gScore + heuristic(*neighborNode, *goalNode);

                // Добавляем в очередь, даже если он там уже есть (с худшим fScore).
                // Проверка closedSet при извлечении отсеет старые записи.
                openSetQueue.push({fScore[neighborId], neighborId});
                openSetTrack[neighborId] = true;  // Отмечаем, что он в "активном рассмотрении"
            }
        }
        if (iterations % 5000 == 0)
        {  // Логгирование прогресса для очень больших поисков
            qCDebug(aStarLog) << "A* iteration:" << iterations << "OpenSet (PQueue) size:" << openSetQueue.size()
                              << "Current ID:" << currentId;
        }
    }

    qCWarning(aStarLog) << "A* Search: Goal not reached after" << timer.elapsed() << "ms and" << iterations
                        << "iterations. Start:" << startWaypointId << "Goal:" << goalWaypointId;
    return {};  // Путь не найден
}

}  // namespace Pathfinding
}  // namespace Core
