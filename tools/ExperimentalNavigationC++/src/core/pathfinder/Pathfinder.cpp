#include "Pathfinder.h"
#include "core/generator/NavMeshGenerator.h"
#include "shared/Logger.h"

#include <algorithm>
#include <cmath>
#include <queue>
#include <unordered_map>
#include <vector>

// Узел для A*. Теперь это простая структура, которую можно безопасно
// копировать.
struct PathNode {
  int x, z;
  int y_idx; // Y-индекс пола
  double g = 0.0, h = 0.0, f = 0.0;
  int parent_idx = -1; // Индекс родителя в allNodes

  // Для priority_queue (min-heap)
  bool operator>(const PathNode &other) const { return f > other.f; }
};

Pathfinder::Pathfinder() {}

double heuristic(int x1, int z1, int x2, int z2) {
  return std::sqrt(pow(x1 - x2, 2) + pow(z1 - z2, 2));
}

std::optional<std::vector<Vector3d>>
Pathfinder::findPath(const NavMeshGenerator *generator,
                     const Vector3d &startPos, const Vector3d &endPos) {

  if (!generator) {
    qCritical(lcCore) << "Pathfinder error: NavMeshGenerator is null.";
    return std::nullopt;
  }

  int startX, startY_idx, startZ;
  int endX, endY_idx, endZ;

  if (!generator->findClosestWalkableVoxel(startPos, startX, startY_idx,
                                           startZ) ||
      !generator->findClosestWalkableVoxel(endPos, endX, endY_idx, endZ)) {
    qWarning(lcCore)
        << "Could not find a walkable voxel near start or end position.";
    return std::nullopt;
  }

  qInfo(lcCore) << "A* Pathfinder on Heightfield started. From (" << startX
                << "," << startZ << ") to (" << endX << "," << endZ << ")";

  // --- НОВАЯ, НАДЕЖНАЯ РЕАЛИЗАЦИЯ A* ---

  std::priority_queue<PathNode, std::vector<PathNode>, std::greater<PathNode>>
      openSet;
  // Ключ - простой 1D-индекс ячейки. Значение - сам узел.
  std::unordered_map<int, PathNode> allNodes;

  // Создаем стартовый узел
  PathNode startNode;
  startNode.x = startX;
  startNode.z = startZ;
  startNode.y_idx = startY_idx;
  startNode.g = 0.0;
  startNode.h = heuristic(startX, startZ, endX, endZ);
  startNode.f = startNode.h;

  int startIndex =
      startX + startZ * generator->getConfig().gridWidth; // Нужен gridWidth
  allNodes[startIndex] = startNode;
  openSet.push(startNode);

  while (!openSet.empty()) {
    PathNode current = openSet.top();
    openSet.pop();

    int current_idx = current.x + current.z * generator->getConfig().gridWidth;

    // Если мы достали из очереди узел, который уже был обработан с лучшей
    // стоимостью, пропускаем
    if (current.g > allNodes[current_idx].g) {
      continue;
    }

    // Проверка на финиш
    if (current.x == endX && current.z == endZ) {
      qInfo(lcCore) << "Path found!";
      std::vector<Vector3d> path;
      PathNode p = current;
      while (p.parent_idx != -1) {
        path.push_back(generator->gridToWorld(p.x, p.y_idx, p.z));
        p = allNodes[p.parent_idx];
      }
      path.push_back(generator->gridToWorld(startX, startY_idx, startZ));
      std::reverse(path.begin(), path.end());
      path.push_back(endPos);
      return path;
    }

    // Перебираем 8 соседей
    for (int dz = -1; dz <= 1; ++dz) {
      for (int dx = -1; dx <= 1; ++dx) {
        if (dx == 0 && dz == 0)
          continue;

        int nx = current.x + dx;
        int nz = current.z + dz;

        int neighbor_y_idx;
        if (generator->isWalkable(current.x, current.z, current.y_idx, nx, nz,
                                  neighbor_y_idx)) {
          double move_cost = (dx == 0 || dz == 0) ? 1.0 : 1.414;
          double new_g = current.g + move_cost;

          int neighbor_idx = nx + nz * generator->getConfig().gridWidth;

          // Если мы нашли более короткий путь до соседа (или нашли его впервые)
          if (allNodes.find(neighbor_idx) == allNodes.end() ||
              new_g < allNodes[neighbor_idx].g) {
            PathNode neighborNode;
            neighborNode.x = nx;
            neighborNode.z = nz;
            neighborNode.y_idx = neighbor_y_idx;
            neighborNode.g = new_g;
            neighborNode.h = heuristic(nx, nz, endX, endZ);
            neighborNode.f = new_g + neighborNode.h;
            neighborNode.parent_idx = current_idx;

            allNodes[neighbor_idx] = neighborNode;
            openSet.push(neighborNode);
          }
        }
      }
    }
  }

  qWarning(lcCore) << "Path not found.";
  return std::nullopt;
}