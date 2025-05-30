#pragma once

#include <QList>
#include <QVector3D>   // Для Waypoint::coordinates, если используется в эвристике
#include <QHash>       // Для gScore, fScore, cameFrom
#include <QMap>        // Для openSet (альтернатива priority_queue)
#include <queue>       // Для std::priority_queue
#include <limits>      // Для std::numeric_limits
#include <functional>  // Для std::function, если будем делать costFunction

// Включаем Waypoint, так как A* напрямую с ним работает (пока)
#include "core/MapData/Waypoint.h"
#include "core/MapData/MapData.h"  // Для Obstacle, если LoS используется внутри A*

// Опционально, если LoS будет вызываться из A* (например, для динамической проверки связей)
// #include "core/LoS/LineOfSight.h"

// Объявление категории логирования (определение будет в .cpp)
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(aStarLog)

namespace Core
{
namespace Pathfinding
{

/**
 * @brief Рассчитывает эвристическое расстояние (обычно евклидово) между двумя вейпоинтами.
 * @param a Первый вейпоинт.
 * @param b Второй вейпоинт.
 * @return Эвристическое расстояние.
 */
double heuristic(const Waypoint& a, const Waypoint& b);

/**
 * @brief Реализация алгоритма A* для поиска кратчайшего пути в графе вейпоинтов.
 *
 * @param mapData Данные карты, содержащие все вейпоинты и, возможно, препятствия (если LoS проверяется).
 * @param startId ID начального вейпоинта.
 * @param goalId ID целевого вейпоинта.
 * @return Список ID вейпоинтов, составляющих путь от startId до goalId. Если путь не найден, возвращает пустой список.
 *         Путь включает начальную и конечную точки.
 */
QList<int> findPathAStar(const MapData& mapData,  // Передаем MapData целиком для доступа к waypoints и obstacles
                         int startWaypointId, int goalWaypointId
                         // TODO: В будущем можно добавить параметры для costFunction, isValidConnection и т.д.
                         // const QList<Obstacle>& obstacles // Если A* будет сам проверять LoS для связей (пока это
                         // делает MainWindow при генерации связей)
);

// Вспомогательная структура для использования в priority_queue
// typedef std::pair<double, int> PQueuePair;
// struct ComparePathNode {
//     bool operator()(const PQueuePair& a, const PQueuePair& b) const {
//         return a.first > b.first; // Min-heap
//     }
// };

}  // namespace Pathfinding
}  // namespace Core
