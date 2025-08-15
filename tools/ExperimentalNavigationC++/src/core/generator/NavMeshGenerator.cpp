#include "NavMeshGenerator.h"
#include "shared/Logger.h"
#include <limits>

NavMeshGenerator::NavMeshGenerator(const NavMeshConfig &config)
    : m_config(config) {
  qInfo(lcCore) << "NavMeshGenerator created.";
}

bool NavMeshGenerator::build(const MeshData &meshData,
                             const ProgressCallback &progressCallback) {
  qInfo(lcCore) << "NavMesh generation started (Full 3D Voxel Pipeline)...";
  m_debugGrids.clear(); // Очищаем старые отладочные данные

  if (meshData.vertices.empty()) {
    qWarning(lcCore) << "MeshData is empty. Aborting build.";
    return false;
  }

  calculateBounds(meshData.vertices);

  // --- ЭТАП 1: Создаем "сырую" карту ВСЕХ препятствий ---
  VoxelGrid solidGrid = Voxelizer::createSolidVoxels(
      meshData, m_config.cellSize, m_config.cellHeight, m_boundsMin,
      m_boundsMax);
  m_debugGrids[VoxelizationStage::Solid] = solidGrid; // Сохраняем для отладки

  if (solidGrid.solidVoxels.empty()) {
    qWarning(lcCore)
        << "Solid voxel grid is empty after stage 1. No geometry found?";
    return false;
  }

  // --- ЭТАП 2: Находим все возможные полы ---
  VoxelGrid floorGrid = Voxelizer::filterWalkableFloors(solidGrid);
  m_debugGrids[VoxelizationStage::WalkableFloors] =
      floorGrid; // Сохраняем для отладки

  // --- ЭТАП 3: Фильтруем полы по высоте агента ---
  VoxelGrid heightFilteredGrid = Voxelizer::filterByAgentHeight(
      floorGrid, solidGrid, m_config.agentHeight, m_config.cellHeight);
  m_debugGrids[VoxelizationStage::HeightFiltered] =
      heightFilteredGrid; // Сохраняем для отладки

  // --- ЭТАП 4: Фильтруем по радиусу агента ---
  m_finalVoxelGrid = Voxelizer::filterByAgentRadius(
      heightFilteredGrid, solidGrid, m_config.agentRadius, m_config.cellSize);
  m_debugGrids[VoxelizationStage::FinalWalkable] =
      m_finalVoxelGrid; // Сохраняем для отладки

  qInfo(lcCore)
      << "NavMesh generation pipeline complete. Walkable grid is ready.";
  return true;
}

const VoxelGrid &
NavMeshGenerator::getDebugVoxelGrid(VoxelizationStage stage) const {
  // Ищем сетку в карте. Если не найдена, возвращаем пустую.
  auto it = m_debugGrids.find(stage);
  if (it != m_debugGrids.end()) {
    return it->second;
  }
  // Этот статический экземпляр будет возвращен, если ничего не найдено.
  // Это безопаснее, чем выбрасывать исключение или возвращать висячую ссылку.
  static const VoxelGrid emptyGrid;
  qWarning(lcCore)
      << "Requested debug voxel grid for a stage that was not found.";
  return emptyGrid;
}

void NavMeshGenerator::calculateBounds(const std::vector<Vector3d> &vertices) {
  if (vertices.empty())
    return;
  m_boundsMin = vertices[0];
  m_boundsMax = vertices[0];
  for (const auto &v : vertices) {
    m_boundsMin = m_boundsMin.cwiseMin(v);
    m_boundsMax = m_boundsMax.cwiseMax(v);
  }
}

bool NavMeshGenerator::worldToGrid(const Vector3d &worldPos, int &gridX,
                                   int &gridY, int &gridZ) const {
  if (m_finalVoxelGrid.gridWidth == 0)
    return false;
  gridX = static_cast<int>(
      floor((worldPos.x() - m_boundsMin.x()) / m_config.cellSize));
  gridZ = static_cast<int>(
      floor((worldPos.y() - m_boundsMin.y()) / m_config.cellSize));
  gridY = static_cast<int>(
      floor((worldPos.z() - m_boundsMin.z()) / m_config.cellHeight));

  return gridX >= 0 && gridX < m_finalVoxelGrid.gridWidth && gridY >= 0 &&
         gridY < m_finalVoxelGrid.gridHeight && gridZ >= 0 &&
         gridZ < m_finalVoxelGrid.gridDepth;
}

Vector3d NavMeshGenerator::gridToWorld(int gridX, int gridY, int gridZ) const {
  return {m_boundsMin.x() + (gridX + 0.5) * m_config.cellSize,
          m_boundsMin.y() + (gridZ + 0.5) * m_config.cellSize,
          m_boundsMin.z() + (gridY + 0.5) * m_config.cellHeight};
}

bool NavMeshGenerator::isWalkable(int x, int y, int z) const {
  if (x < 0 || x >= m_finalVoxelGrid.gridWidth || y < 0 ||
      y >= m_finalVoxelGrid.gridHeight || z < 0 ||
      z >= m_finalVoxelGrid.gridDepth) {
    return false;
  }
  size_t index = m_finalVoxelGrid.getVoxelIndex(x, y, z);
  return m_finalVoxelGrid.solidVoxels[index];
}

bool NavMeshGenerator::findClosestWalkableVoxel(const Vector3d &worldPos,
                                                int &outX, int &outY,
                                                int &outZ) const {
  int initialX, initialY, initialZ;
  if (!worldToGrid(worldPos, initialX, initialY, initialZ)) {
    qWarning(lcCore)
        << "Start/end position is outside the generated navmesh bounds.";
    return false;
  }

  if (isWalkable(initialX, initialY, initialZ)) {
    outX = initialX;
    outY = initialY;
    outZ = initialZ;
    return true;
  }

  const int maxSearchRadius = 50;
  for (int radius = 1; radius < maxSearchRadius; ++radius) {
    for (int y = -radius; y <= radius; ++y) {
      for (int z = -radius; z <= radius; ++z) {
        for (int x = -radius; x <= radius; ++x) {
          if (abs(x) != radius && abs(y) != radius && abs(z) != radius)
            continue;
          int checkX = initialX + x;
          int checkY = initialY + y;
          int checkZ = initialZ + z;
          if (isWalkable(checkX, checkY, checkZ)) {
            outX = checkX;
            outY = checkY;
            outZ = checkZ;
            qInfo(lcCore) << "Found closest walkable voxel at offset (" << x
                          << "," << y << "," << z << ")";
            return true;
          }
        }
      }
    }
  }

  qWarning(lcCore) << "Could not find any walkable voxel within radius"
                   << maxSearchRadius;
  return false;
}