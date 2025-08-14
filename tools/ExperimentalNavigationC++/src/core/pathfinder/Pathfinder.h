#pragma once

#include "../math/Types.h"
#include <optional>
#include <vector>

class NavMeshGenerator;

class Pathfinder {
public:
  Pathfinder();

  std::optional<std::vector<Vector3d>>
  findPath(const NavMeshGenerator *generator, const Vector3d &startPos,
           const Vector3d &endPos);
};