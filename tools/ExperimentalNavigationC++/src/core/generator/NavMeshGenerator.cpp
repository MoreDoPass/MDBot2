#include "NavMeshGenerator.h"
#include "pipeline/MeshFilter.h"
#include "pipeline/VoxelCoster.h" // <-- Подключаем наш новый инструмент
#include "shared/Logger.h"
#include <limits>

NavMeshGenerator::NavMeshGenerator(const NavMeshConfig &config)
    : m_config(config) {
  qInfo(lcCore) << "NavMeshGenerator created.";
}

bool NavMeshGenerator::build(const MeshData &meshData,
                             const ProgressCallback &progressCallback) {
  qInfo(lcCore) << "NavMesh generation started (Full Pipeline)...";
  m_debugGrids.clear();
  m_voxelCosts.clear();
  m_solidGrid.solidVoxels.clear();

  if (meshData.vertices.empty()) {
    qWarning(lcCore) << "MeshData is empty. Aborting build.";
    return false;
  }

  calculateBounds(meshData.vertices);

  m_gridWidth = static_cast<int>(
      ceil((m_boundsMax.x() - m_boundsMin.x()) / m_config.cellSize));
  m_gridDepth = static_cast<int>(
      ceil((m_boundsMax.y() - m_boundsMin.y()) / m_config.cellSize));
  m_gridHeight = static_cast<int>(
      ceil((m_boundsMax.z() - m_boundsMin.z()) / m_config.cellHeight));

  if (m_gridWidth == 0 || m_gridHeight == 0 || m_gridDepth == 0) {
    qCritical(lcCore)
        << "Grid dimensions are zero after bounds calculation. Aborting.";
    return false;
  }

  // ======================================================================
  // === КОНВЕЙЕР 1: ДАННЫЕ ДЛЯ РЕЙКАСТИНГА И ПРОВЕРКИ ОБРЫВОВ         ===
  // ======================================================================
  qInfo(lcCore) << "[Pipeline 1/2] Generating solid grid for collision...";
  m_solidGrid = Voxelizer::createSolidVoxels(meshData, m_config.cellSize,
                                             m_config.cellHeight, m_boundsMin,
                                             m_boundsMax);
  m_debugGrids[VoxelizationStage::Solid] = m_solidGrid;

  // ======================================================================
  // === КОНВЕЙЕР 2: ДАННЫЕ ДЛЯ ПЕШЕЙ НАВИГАЦИИ                        ===
  // ======================================================================
  qInfo(lcCore) << "[Pipeline 2/2] Generating walkable navigation data...";

  // --- ВРЕМЕННОЕ ИСПРАВЛЕНИЕ: Мы пока не используем фильтр по углу, ---
  // --- так как он ломает `filterWalkableFloors`.                   ---
  // --- Вместо этого, все последующие фильтры будут работать с      ---
  // --- полной картой `m_solidGrid`, как это было раньше.            ---

  // MeshData walkableMesh = MeshFilter::filterBySlope(meshData,
  // m_config.agentMaxSlope); VoxelGrid walkableSolidGrid =
  // Voxelizer::createSolidVoxels(
  //     walkableMesh, m_config.cellSize, m_config.cellHeight, m_boundsMin,
  //     m_boundsMax);

  // Используем m_solidGrid, в котором есть стены, для корректного поиска полов.
  VoxelGrid floorGrid = Voxelizer::filterWalkableFloors(m_solidGrid);
  m_debugGrids[VoxelizationStage::WalkableFloors] = floorGrid;

  // Для проверки высоты также используем m_solidGrid
  VoxelGrid heightFilteredGrid = Voxelizer::filterByAgentHeight(
      floorGrid, m_solidGrid, m_config.agentHeight, m_config.cellHeight);
  m_debugGrids[VoxelizationStage::HeightFiltered] = heightFilteredGrid;

  VoxelGrid radiusFilteredGrid = Voxelizer::filterByAgentRadius(
      heightFilteredGrid, m_solidGrid, m_config.agentRadius, m_config.cellSize);
  m_debugGrids[VoxelizationStage::RadiusFiltered] = radiusFilteredGrid;
  m_debugGrids[VoxelizationStage::FinalWalkable] = radiusFilteredGrid;

  m_voxelCosts = VoxelCoster::calculateCosts(radiusFilteredGrid, m_solidGrid);

  qInfo(lcCore) << "Full pipeline finished. NavMesh is ready.";
  return true;
}

const VoxelGrid &
NavMeshGenerator::getDebugVoxelGrid(VoxelizationStage stage) const {
  auto it = m_debugGrids.find(stage);
  if (it != m_debugGrids.end()) {
    return it->second;
  }
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
  // --- ИСПРАВЛЕНИЕ: Убираем отсюда расчет размеров сетки ---
}

bool NavMeshGenerator::worldToGrid(const Vector3d &worldPos, int &gridX,
                                   int &gridY, int &gridZ) const {
  if (m_gridWidth == 0)
    return false;
  gridX = static_cast<int>(
      floor((worldPos.x() - m_boundsMin.x()) / m_config.cellSize));
  gridZ = static_cast<int>(
      floor((worldPos.y() - m_boundsMin.y()) / m_config.cellSize));
  gridY = static_cast<int>(
      floor((worldPos.z() - m_boundsMin.z()) / m_config.cellHeight));

  return gridX >= 0 && gridX < m_gridWidth && gridY >= 0 &&
         gridY < m_gridHeight && gridZ >= 0 && gridZ < m_gridDepth;
}

Vector3d NavMeshGenerator::gridToWorld(int gridX, int gridY, int gridZ) const {
  return {m_boundsMin.x() + (gridX + 0.5) * m_config.cellSize,
          m_boundsMin.y() + (gridZ + 0.5) * m_config.cellSize,
          m_boundsMin.z() + (gridY + 0.5) * m_config.cellHeight};
}

uint8_t NavMeshGenerator::getVoxelCost(int x, int y, int z) const {
  if (x < 0 || x >= m_gridWidth || y < 0 || y >= m_gridHeight || z < 0 ||
      z >= m_gridDepth) {
    return 0; // Непроходимо, если за границами
  }
  size_t index = (size_t)x + (size_t)z * m_gridWidth +
                 (size_t)y * m_gridWidth * m_gridDepth;
  return m_voxelCosts[index];
}

bool NavMeshGenerator::isWalkable(int x, int y, int z) const {
  // Воксель проходим, если его стоимость больше нуля.
  return getVoxelCost(x, y, z) > 0;
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

bool NavMeshGenerator::isSolid(int x, int y, int z) const {
  if (x < 0 || x >= m_gridWidth || y < 0 || y >= m_gridHeight || z < 0 ||
      z >= m_gridDepth || m_solidGrid.solidVoxels.empty()) {
    // За пределами карты считаем, что препятствий нет, чтобы луч мог "выйти"
    // за сцену. Если считать, что там стена, луч всегда будет во что-то
    // упираться.
    return false;
  }
  size_t index = (size_t)x + (size_t)z * m_gridWidth +
                 (size_t)y * m_gridWidth * m_gridDepth;

  if (index >= m_solidGrid.solidVoxels.size()) {
    qWarning(lcCore) << "isSolid check is out of bounds:" << index;
    return false;
  }
  return m_solidGrid.solidVoxels[index];
}

bool NavMeshGenerator::raycast(const Vector3d &start,
                               const Vector3d &end) const {
  int x0, y0, z0;
  int x1, y1, z1;

  // Если начальная или конечная точка вне сетки, для безопасности считаем,
  // что препятствие есть.
  if (!worldToGrid(start, x0, y0, z0) || !worldToGrid(end, x1, y1, z1)) {
    qWarning(lcCore)
        << "Raycast failed: start or end point is outside the grid.";
    return true;
  }

  // Реализация 3D-алгоритма Брезенхэма
  int dx = std::abs(x1 - x0);
  int dy = std::abs(y1 - y0);
  int dz = std::abs(z1 - z0);

  int xs = (x0 < x1) ? 1 : -1;
  int ys = (y0 < y1) ? 1 : -1;
  int zs = (z0 < z1) ? 1 : -1;

  // Проверяем начальную точку
  if (isSolid(x0, y0, z0))
    return true;

  // Ведущая ось X
  if (dx >= dy && dx >= dz) {
    int p1 = 2 * dy - dx;
    int p2 = 2 * dz - dx;
    while (x0 != x1) {
      x0 += xs;
      if (p1 >= 0) {
        y0 += ys;
        p1 -= 2 * dx;
      }
      if (p2 >= 0) {
        z0 += zs;
        p2 -= 2 * dx;
      }
      p1 += 2 * dy;
      p2 += 2 * dz;
      if (isSolid(x0, y0, z0))
        return true;
    }
  }
  // Ведущая ось Y
  else if (dy >= dx && dy >= dz) {
    int p1 = 2 * dx - dy;
    int p2 = 2 * dz - dy;
    while (y0 != y1) {
      y0 += ys;
      if (p1 >= 0) {
        x0 += xs;
        p1 -= 2 * dy;
      }
      if (p2 >= 0) {
        z0 += zs;
        p2 -= 2 * dy;
      }
      p1 += 2 * dx;
      p2 += 2 * dz;
      if (isSolid(x0, y0, z0))
        return true;
    }
  }
  // Ведущая ось Z
  else {
    int p1 = 2 * dy - dz;
    int p2 = 2 * dx - dz;
    while (z0 != z1) {
      z0 += zs;
      if (p1 >= 0) {
        y0 += ys;
        p1 -= 2 * dz;
      }
      if (p2 >= 0) {
        x0 += xs;
        p2 -= 2 * dz;
      }
      p1 += 2 * dy;
      p2 += 2 * dx;
      if (isSolid(x0, y0, z0))
        return true;
    }
  }

  // Если дошли до конца и не нашли препятствий
  return false;
}