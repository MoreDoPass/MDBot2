#include "NavMeshGenerator.h"
#include "shared/Logger.h"
#include <algorithm>
#include <cmath>
#include <limits>

namespace {
bool triBoxOverlap(const Vector3d &boxcenter, const Vector3d &boxhalfsize,
                   const Vector3d &tv0, const Vector3d &tv1,
                   const Vector3d &tv2) {
  Vector3d tri_min = tv0.cwiseMin(tv1).cwiseMin(tv2);
  Vector3d tri_max = tv0.cwiseMax(tv1).cwiseMax(tv2);
  Vector3d box_min = boxcenter - boxhalfsize;
  Vector3d box_max = boxcenter + boxhalfsize;
  return (box_min.x() <= tri_max.x() && box_max.x() >= tri_min.x()) &&
         (box_min.y() <= tri_max.y() && box_max.y() >= tri_min.y()) &&
         (box_min.z() <= tri_max.z() && box_max.z() >= tri_min.z());
}
} // namespace

NavMeshGenerator::NavMeshGenerator(const NavMeshConfig &config)
    : m_config(config) {
  qInfo(lcCore) << "NavMeshGenerator created.";
}

bool NavMeshGenerator::build(const MeshData &meshData,
                             const ProgressCallback &progressCallback) {
  if (meshData.vertices.empty() || meshData.indices.empty()) {
    qWarning(lcCore) << "Cannot build NavMesh, mesh data is empty.";
    return false;
  }
  qInfo(lcCore) << "NavMesh generation started...";

  // Этап 1: Вокселизация
  calculateBounds(meshData.vertices);
  createSolidVoxels(meshData, progressCallback);

  // Этап 2: Построение карты высот
  buildHeightfield();

  // Следующие этапы будут здесь. Пока что мы останавливаемся на этом.
  qInfo(lcCore)
      << "Initial generation steps (Voxelization, Heightfield) are complete.";
  return true;
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
  m_gridWidth = static_cast<int>((m_boundsMax.x() - m_boundsMin.x()) /
                                 m_config.cellSize) +
                1;
  m_gridDepth = static_cast<int>((m_boundsMax.y() - m_boundsMin.y()) /
                                 m_config.cellSize) +
                1;
  m_gridHeight = static_cast<int>((m_boundsMax.z() - m_boundsMin.z()) /
                                  m_config.cellHeight) +
                 1;

  m_config.gridWidth = m_gridWidth;
  m_config.gridDepth = m_gridDepth;

  qInfo(lcCore) << "Calculated bounds: Min(" << m_boundsMin.x()
                << m_boundsMin.y() << m_boundsMin.z() << "), Max("
                << m_boundsMax.x() << m_boundsMax.y() << m_boundsMax.z() << ")";
  qInfo(lcCore) << "Voxel grid dimensions (Width/X, Depth/Y, Height/Z):"
                << m_gridWidth << "x" << m_gridDepth << "x" << m_gridHeight;
}

void NavMeshGenerator::createSolidVoxels(
    const MeshData &meshData, const ProgressCallback &progressCallback) {
  qInfo(lcCore) << "Creating solid voxels...";
  size_t totalVoxels = (size_t)m_gridWidth * m_gridHeight * m_gridDepth;
  m_solidVoxels.assign(totalVoxels, false);
  const Vector3d boxhalfsize(m_config.cellSize / 2.0, m_config.cellSize / 2.0,
                             m_config.cellHeight / 2.0);
  int solid_count = 0;
  const size_t totalTriangles = meshData.indices.size();
  size_t processedTriangles = 0;
  int lastReportedProgress = -1;

  for (const auto &tri_indices : meshData.indices) {
    processedTriangles++;
    if (progressCallback && totalTriangles > 0) {
      int progress =
          static_cast<int>((processedTriangles * 100) / totalTriangles);
      if (progress > lastReportedProgress) {
        lastReportedProgress = progress;
        progressCallback(progress);
      }
    }
    const Vector3d &v0 = meshData.vertices[tri_indices[0]];
    const Vector3d &v1 = meshData.vertices[tri_indices[1]];
    const Vector3d &v2 = meshData.vertices[tri_indices[2]];
    Vector3d tri_min = v0.cwiseMin(v1).cwiseMin(v2);
    Vector3d tri_max = v0.cwiseMax(v1).cwiseMax(v2);
    int min_x = static_cast<int>(
        floor((tri_min.x() - m_boundsMin.x()) / m_config.cellSize));
    int max_x = static_cast<int>(
        ceil((tri_max.x() - m_boundsMin.x()) / m_config.cellSize));
    int min_z = static_cast<int>(
        floor((tri_min.y() - m_boundsMin.y()) / m_config.cellSize));
    int max_z = static_cast<int>(
        ceil((tri_max.y() - m_boundsMin.y()) / m_config.cellSize));
    int min_y = static_cast<int>(
        floor((tri_min.z() - m_boundsMin.z()) / m_config.cellHeight));
    int max_y = static_cast<int>(
        ceil((tri_max.z() - m_boundsMin.z()) / m_config.cellHeight));

    for (int y_idx = min_y; y_idx <= max_y; ++y_idx) {
      for (int z_idx = min_z; z_idx <= max_z; ++z_idx) {
        for (int x_idx = min_x; x_idx <= max_x; ++x_idx) {
          if (x_idx < 0 || x_idx >= m_gridWidth || y_idx < 0 ||
              y_idx >= m_gridHeight || z_idx < 0 || z_idx >= m_gridDepth)
            continue;
          size_t index = x_idx + z_idx * m_gridWidth +
                         y_idx * (size_t)m_gridWidth * m_gridDepth;
          if (m_solidVoxels[index])
            continue;
          Vector3d boxcenter = {
              m_boundsMin.x() + (x_idx + 0.5) * m_config.cellSize,
              m_boundsMin.y() + (z_idx + 0.5) * m_config.cellSize,
              m_boundsMin.z() + (y_idx + 0.5) * m_config.cellHeight};
          if (triBoxOverlap(boxcenter, boxhalfsize, v0, v1, v2)) {
            m_solidVoxels[index] = true;
            solid_count++;
          }
        }
      }
    }
  }
  qInfo(lcCore) << "Solid voxelization complete. Found" << solid_count
                << "solid voxels.";
}

void NavMeshGenerator::buildHeightfield() {
  qInfo(lcCore) << "Building heightfield...";
  m_heightfield.assign((size_t)m_gridWidth * m_gridDepth, {});
  for (int z_idx = 0; z_idx < m_gridDepth; ++z_idx) {
    for (int x_idx = 0; x_idx < m_gridWidth; ++x_idx) {
      bool is_solid_under = true;
      for (int y_idx = 0; y_idx < m_gridHeight; ++y_idx) {
        size_t index = x_idx + z_idx * m_gridWidth +
                       y_idx * (size_t)m_gridWidth * m_gridDepth;
        bool is_solid_now = m_solidVoxels[index];
        if (is_solid_under && !is_solid_now) {
          // Нашли пол!
          HeightfieldSpan span;
          span.min = y_idx;
          span.max = y_idx;
          while (y_idx + 1 < m_gridHeight) {
            size_t next_index = x_idx + z_idx * m_gridWidth +
                                (y_idx + 1) * (size_t)m_gridWidth * m_gridDepth;
            if (m_solidVoxels[next_index]) {
              break;
            }
            y_idx++;
            span.max = y_idx;
          }
          int height_in_voxels = span.max - span.min + 1;
          if (height_in_voxels * m_config.cellHeight >= m_config.agentHeight) {
            m_heightfield[x_idx + z_idx * m_gridWidth].push_back(span);
          }
        }
        is_solid_under = is_solid_now;
      }
    }
  }
  size_t totalSpans = 0;
  for (const auto &col : m_heightfield)
    totalSpans += col.size();
  qInfo(lcCore) << "Heightfield built. Found" << totalSpans
                << "walkable spans.";
}

std::vector<Vector3d> NavMeshGenerator::getWalkableVoxelCenters() const {
  std::vector<Vector3d> centers;
  if (m_heightfield.empty())
    return centers;
  for (int z_idx = 0; z_idx < m_gridDepth; ++z_idx) {
    for (int x_idx = 0; x_idx < m_gridWidth; ++x_idx) {
      const size_t columnIndex = x_idx + z_idx * m_gridWidth;
      for (const auto &span : m_heightfield[columnIndex]) {
        centers.push_back(
            {m_boundsMin.x() + (x_idx + 0.5) * m_config.cellSize,
             m_boundsMin.y() + (z_idx + 0.5) * m_config.cellSize,
             m_boundsMin.z() + (span.min + 0.5) * m_config.cellHeight});
      }
    }
  }
  return centers;
}

// --- РЕАЛИЗАЦИЯ УТИЛИТ ДЛЯ БУДУЩЕГО PATHFINDER ---

bool NavMeshGenerator::worldToGrid(const Vector3d &worldPos, int &gridX,
                                   int &gridZ) const {
  gridX = static_cast<int>(
      floor((worldPos.x() - m_boundsMin.x()) / m_config.cellSize));
  gridZ = static_cast<int>(
      floor((worldPos.y() - m_boundsMin.y()) / m_config.cellSize));
  return gridX >= 0 && gridX < m_gridWidth && gridZ >= 0 && gridZ < m_gridDepth;
}

bool NavMeshGenerator::findClosestWalkableVoxel(const Vector3d &worldPos,
                                                int &outX, int &outY,
                                                int &outZ) const {
  int gridX, gridZ_coord;
  if (!worldToGrid(worldPos, gridX, gridZ_coord))
    return false;

  double minDistSq = std::numeric_limits<double>::max();
  bool found = false;

  for (int z = -5; z <= 5; ++z) {
    for (int x = -5; x <= 5; ++x) {
      int currentX = gridX + x;
      int currentZ = gridZ_coord + z;
      if (currentX < 0 || currentX >= m_gridWidth || currentZ < 0 ||
          currentZ >= m_gridDepth)
        continue;
      const auto &spans = m_heightfield[currentX + currentZ * m_gridWidth];
      if (spans.empty())
        continue;
      for (const auto &span : spans) {
        double spanHeight =
            m_boundsMin.z() + (span.min + 0.5) * m_config.cellHeight;
        double distSq = std::pow(currentX - gridX, 2) +
                        std::pow(currentZ - gridZ_coord, 2) +
                        std::pow(spanHeight - worldPos.z(), 2);
        if (distSq < minDistSq) {
          minDistSq = distSq;
          outX = currentX;
          outY = span.min;
          outZ = currentZ;
          found = true;
        }
      }
    }
  }
  return found;
}

Vector3d NavMeshGenerator::gridToWorld(int gridX, int gridY, int gridZ) const {
  return {m_boundsMin.x() + (gridX + 0.5) * m_config.cellSize,
          m_boundsMin.y() + (gridZ + 0.5) * m_config.cellSize,
          m_boundsMin.z() + (gridY + 0.5) * m_config.cellHeight};
}

bool NavMeshGenerator::isWalkable(int startX, int startZ, int startY_idx,
                                  int endX, int endZ, int &endY_idx) const {
  if (endX < 0 || endX >= m_gridWidth || endZ < 0 || endZ >= m_gridDepth)
    return false;
  const auto &endSpans = m_heightfield[endX + endZ * m_gridWidth];
  if (endSpans.empty())
    return false;
  const double startHeight =
      m_boundsMin.z() + (startY_idx + 0.5) * m_config.cellHeight;
  for (const auto &span : endSpans) {
    const double endHeight =
        m_boundsMin.z() + (span.min + 0.5) * m_config.cellHeight;
    if (std::abs(startHeight - endHeight) < m_config.agentMaxClimb) {
      endY_idx = span.min;
      return true;
    }
  }
  return false;
}