#include "Pathfinder.h"
#include "core/generator/NavMeshGenerator.h"
#include "shared/Logger.h"

#include <algorithm>
#include <cmath>
#include <queue>
#include <unordered_map>
#include <vector>

struct PathNode {
  int x, y, z;
  double g = 0.0, h = 0.0, f = 0.0;
  size_t parent_idx = -1;
  bool operator>(const PathNode &other) const { return f > other.f; }
};

Pathfinder::Pathfinder() {}

double heuristic(int x1, int y1, int z1, int x2, int y2, int z2) {
  return std::sqrt(pow(x1 - x2, 2.0) + pow(y1 - y2, 2.0) + pow(z1 - z2, 2.0));
}

std::optional<std::vector<Vector3d>>
Pathfinder::findPath(const NavMeshGenerator *generator,
                     const Vector3d &startPos, const Vector3d &endPos) {
  if (!generator)
    return std::nullopt;

  int startX, startY, startZ;
  int endX, endY, endZ;

  if (!generator->findClosestWalkableVoxel(startPos, startX, startY, startZ) ||
      !generator->findClosestWalkableVoxel(endPos, endX, endY, endZ)) {
    qWarning(lcCore)
        << "Could not find a walkable voxel near start or end position.";
    return std::nullopt;
  }

  qInfo(lcCore) << "3D A* Pathfinder started. From grid (" << startX << ","
                << startY << "," << startZ << ") to (" << endX << "," << endY
                << "," << endZ << ")";

  std::priority_queue<PathNode, std::vector<PathNode>, std::greater<PathNode>>
      openSet;
  std::unordered_map<size_t, PathNode> allNodes;
  const VoxelGrid &walkableGrid = generator->getVoxelGrid();

  PathNode startNode;
  startNode.x = startX;
  startNode.y = startY;
  startNode.z = startZ;
  startNode.h = heuristic(startX, startY, startZ, endX, endY, endZ);
  startNode.f = startNode.h;

  size_t startIndex = walkableGrid.getVoxelIndex(startX, startY, startZ);
  allNodes[startIndex] = startNode;
  openSet.push(startNode);

  const int maxIterations = 5000000;
  int iterations = 0;

  while (!openSet.empty() && iterations < maxIterations) {
    iterations++;
    PathNode current = openSet.top();
    openSet.pop();

    size_t currentIndex =
        walkableGrid.getVoxelIndex(current.x, current.y, current.z);
    if (current.g > allNodes[currentIndex].g)
      continue;

    if (current.x == endX && current.y == endY && current.z == endZ) {
      qInfo(lcCore) << "Path found in" << iterations << "iterations.";
      std::vector<Vector3d> path;
      PathNode p = current;
      while (p.parent_idx != -1) {
        path.push_back(generator->gridToWorld(p.x, p.y, p.z));
        p = allNodes[p.parent_idx];
      }
      path.push_back(generator->gridToWorld(startX, startY, startZ));
      std::reverse(path.begin(), path.end());
      return path;
    }

    for (int dy = -1; dy <= 1; ++dy) {
      for (int dz = -1; dz <= 1; ++dz) {
        for (int dx = -1; dx <= 1; ++dx) {
          if (dx == 0 && dy == 0 && dz == 0)
            continue;

          int nx = current.x + dx;
          int ny = current.y + dy;
          int nz = current.z + dz;

          if (nx < 0 || nx >= walkableGrid.gridWidth || ny < 0 ||
              ny >= walkableGrid.gridHeight || nz < 0 ||
              nz >= walkableGrid.gridDepth)
            continue;

          size_t neighborIndex = walkableGrid.getVoxelIndex(nx, ny, nz);
          if (walkableGrid.solidVoxels[neighborIndex]) {
            double move_cost = std::sqrt(dx * dx + dy * dy + dz * dz);
            double new_g = current.g + move_cost;

            if (allNodes.find(neighborIndex) == allNodes.end() ||
                new_g < allNodes[neighborIndex].g) {
              PathNode neighborNode;
              neighborNode.x = nx;
              neighborNode.y = ny;
              neighborNode.z = nz;
              neighborNode.g = new_g;
              neighborNode.h = heuristic(nx, ny, nz, endX, endY, endZ);
              neighborNode.f = new_g + neighborNode.h;
              neighborNode.parent_idx = currentIndex;
              allNodes[neighborIndex] = neighborNode;
              openSet.push(neighborNode);
            }
          }
        }
      }
    }
  }

  if (iterations >= maxIterations)
    qWarning(lcCore) << "Pathfinding stopped: iteration limit reached.";
  else
    qWarning(lcCore) << "Path not found.";

  return std::nullopt;
}