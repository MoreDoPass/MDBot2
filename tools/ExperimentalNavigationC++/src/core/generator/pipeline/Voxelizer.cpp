#include "Voxelizer.h"
#include "AabbTriangleIntersection.h" // <-- НАШ НОВЫЙ ИНСТРУМЕНТ
#include "shared/Logger.h"
#include <algorithm> // Для std::min/max
#include <cmath>

VoxelGrid Voxelizer::createSolidVoxels(const MeshData &meshData,
                                       double cellSize, double cellHeight,
                                       const Vector3d &boundsMin,
                                       const Vector3d &boundsMax) {
  qInfo(lcCore) << "Voxelizer: Starting ACCURATE solid voxel creation...";

  VoxelGrid grid;
  grid.gridWidth =
      static_cast<int>(ceil((boundsMax.x() - boundsMin.x()) / cellSize));
  grid.gridDepth =
      static_cast<int>(ceil((boundsMax.y() - boundsMin.y()) / cellSize));
  grid.gridHeight =
      static_cast<int>(ceil((boundsMax.z() - boundsMin.z()) / cellHeight));

  if (grid.gridWidth == 0 || grid.gridHeight == 0 || grid.gridDepth == 0) {
    qWarning(lcCore) << "Voxel grid has zero dimension. Aborting voxelization.";
    return grid;
  }

  size_t totalVoxels =
      (size_t)grid.gridWidth * grid.gridHeight * grid.gridDepth;
  grid.solidVoxels.assign(totalVoxels, false);

  int solid_count = 0;

  const float cs = static_cast<float>(cellSize);
  const float ch = static_cast<float>(cellHeight);
  const float ics = 1.0f / cs;
  const float ich = 1.0f / ch;

  // Половинные размеры вокселя для теста на пересечение
  const Vector3f box_halfsize(cs * 0.5f, cs * 0.5f, ch * 0.5f);

  for (const auto &tri_indices : meshData.indices) {
    // Получаем вершины треугольника
    Vector3f tri_verts[3] = {meshData.vertices[tri_indices[0]].cast<float>(),
                             meshData.vertices[tri_indices[1]].cast<float>(),
                             meshData.vertices[tri_indices[2]].cast<float>()};

    // --- Шаг 1: Находим "рамку" (AABB) для треугольника, чтобы сузить поиск
    // ---
    float min_x =
        std::min({tri_verts[0].x(), tri_verts[1].x(), tri_verts[2].x()});
    float max_x =
        std::max({tri_verts[0].x(), tri_verts[1].x(), tri_verts[2].x()});
    float min_y =
        std::min({tri_verts[0].y(), tri_verts[1].y(), tri_verts[2].y()});
    float max_y =
        std::max({tri_verts[0].y(), tri_verts[1].y(), tri_verts[2].y()});
    float min_z =
        std::min({tri_verts[0].z(), tri_verts[1].z(), tri_verts[2].z()});
    float max_z =
        std::max({tri_verts[0].z(), tri_verts[1].z(), tri_verts[2].z()});

    int Imin_x = static_cast<int>(floor((min_x - boundsMin.x()) * ics));
    int Imax_x = static_cast<int>(ceil((max_x - boundsMin.x()) * ics));
    int Imin_z = static_cast<int>(
        floor((min_y - boundsMin.y()) * ics)); // World Y -> Grid Z
    int Imax_z = static_cast<int>(ceil((max_y - boundsMin.y()) * ics));
    int Imin_y = static_cast<int>(
        floor((min_z - boundsMin.z()) * ich)); // World Z -> Grid Y
    int Imax_y = static_cast<int>(ceil((max_z - boundsMin.z()) * ich));

    // --- Шаг 2: Проходим по каждому вокселю ВНУТРИ рамки ---
    for (int iy = Imin_y; iy <= Imax_y; ++iy) {
      for (int iz = Imin_z; iz <= Imax_z; ++iz) {
        for (int ix = Imin_x; ix <= Imax_x; ++ix) {

          if (ix < 0 || ix >= grid.gridWidth || iy < 0 ||
              iy >= grid.gridHeight || iz < 0 || iz >= grid.gridDepth) {
            continue;
          }
          size_t index = grid.getVoxelIndex(ix, iy, iz);
          if (grid.solidVoxels[index]) {
            continue; // Этот воксель уже закрашен, пропускаем
          }

          // --- Шаг 3: Выполняем ТОЧНУЮ проверку (как ты и просил) ---
          // Находим центр текущего вокселя в мировых координатах
          Vector3f box_center(boundsMin.x() + (ix + 0.5f) * cs,
                              boundsMin.y() + (iz + 0.5f) * cs,
                              boundsMin.z() + (iy + 0.5f) * ch);

          // Проверяем, пересекается ли воксель с треугольником
          if (Intersection::triBoxOverlap(box_center, box_halfsize,
                                          tri_verts)) {
            grid.solidVoxels[index] = true;
            solid_count++;
          }
        }
      }
    }
  }

  qInfo(lcCore) << "Voxelizer: Accurate solid voxelization complete. Found"
                << solid_count << "solid voxels.";
  return grid;
}

// --- Остальные функции (filterWalkableFloors, filterByAgentHeight и т.д.) ---
// --- ОСТАЮТСЯ БЕЗ ИЗМЕНЕНИЙ! ---
// ... (скопируй их из своего старого файла или из моего предыдущего ответа) ...
VoxelGrid Voxelizer::filterWalkableFloors(const VoxelGrid &solidGrid) {
  qInfo(lcCore) << "Voxelizer: Filtering walkable floors...";
  VoxelGrid walkableGrid = solidGrid; // Копируем размеры
  if (solidGrid.solidVoxels.empty())
    return walkableGrid;

  walkableGrid.solidVoxels.assign(solidGrid.solidVoxels.size(),
                                  false); // Очищаем

  int walkable_count = 0;
  for (int y = 1; y < solidGrid.gridHeight; ++y) {
    for (int z = 0; z < solidGrid.gridDepth; ++z) {
      for (int x = 0; x < solidGrid.gridWidth; ++x) {
        size_t currentIndex = solidGrid.getVoxelIndex(x, y, z);
        size_t floorIndex = solidGrid.getVoxelIndex(x, y - 1, z);

        // Условие: текущий воксель - воздух, а под ним - твердый пол
        if (!solidGrid.solidVoxels[currentIndex] &&
            solidGrid.solidVoxels[floorIndex]) {
          walkableGrid.solidVoxels[currentIndex] = true;
          walkable_count++;
        }
      }
    }
  }
  qInfo(lcCore) << "Voxelizer: Found" << walkable_count
                << "potential walkable floor voxels.";
  return walkableGrid;
}

VoxelGrid Voxelizer::filterByAgentHeight(const VoxelGrid &walkableFloors,
                                         const VoxelGrid &solidGrid,
                                         double agentHeight,
                                         double cellHeight) {
  qInfo(lcCore) << "Voxelizer: Filtering floors by agent height...";
  VoxelGrid finalGrid = walkableFloors; // Копируем, будем из нее удалять
  if (walkableFloors.solidVoxels.empty())
    return finalGrid;

  const int heightInVoxels = static_cast<int>(ceil(agentHeight / cellHeight));
  int removed_count = 0;

  for (int y = 0; y < finalGrid.gridHeight; ++y) {
    for (int z = 0; z < finalGrid.gridDepth; ++z) {
      for (int x = 0; x < finalGrid.gridWidth; ++x) {
        size_t currentIndex = finalGrid.getVoxelIndex(x, y, z);
        if (finalGrid.solidVoxels[currentIndex]) { // Если это проходимый пол
          // Проверяем пространство над ним
          for (int i = 1; i < heightInVoxels; ++i) {
            int checkY = y + i;
            if (checkY >= solidGrid.gridHeight)
              break; // Дошли до верха мира

            size_t checkIndex = solidGrid.getVoxelIndex(x, checkY, z);
            if (solidGrid.solidVoxels[checkIndex]) {
              // Нашли препятствие над головой!
              finalGrid.solidVoxels[currentIndex] = false;
              removed_count++;
              break; // Переходим к следующему вокселю
            }
          }
        }
      }
    }
  }
  qInfo(lcCore) << "Voxelizer: Removed" << removed_count
                << "voxels due to low clearance.";
  return finalGrid;
}

VoxelGrid Voxelizer::filterByAgentRadius(const VoxelGrid &heightFilteredGrid,
                                         const VoxelGrid &solidGrid,
                                         double agentRadius, double cellSize) {
  qInfo(lcCore) << "Voxelizer: Filtering walkable area by agent radius (SMART "
                   "version)...";
  // ВАЖНО: Мы не можем изменять heightFilteredGrid напрямую,
  // так как нам нужно читать из нее "чистые" данные во время итерации.
  // Поэтому мы создаем новую, финальную сетку.
  VoxelGrid finalGrid = heightFilteredGrid;
  finalGrid.solidVoxels.assign(finalGrid.solidVoxels.size(), false);

  if (heightFilteredGrid.solidVoxels.empty()) {
    qWarning(lcCore)
        << "Input for radius filter is empty. Result will be empty too.";
    return finalGrid;
  }

  const int radiusInVoxels = static_cast<int>(floor(agentRadius / cellSize));
  int removed_count = 0;
  int initial_count = 0;

  for (int y = 0; y < heightFilteredGrid.gridHeight; ++y) {
    for (int z = 0; z < heightFilteredGrid.gridDepth; ++z) {
      for (int x = 0; x < heightFilteredGrid.gridWidth; ++x) {

        size_t currentIndex = heightFilteredGrid.getVoxelIndex(x, y, z);
        // Проверяем, был ли этот воксель проходимым ДО начала нашей проверки
        if (!heightFilteredGrid.solidVoxels[currentIndex]) {
          continue;
        }
        initial_count++; // Считаем, сколько было проходимых вокселей изначально

        bool canStandHere = true;
        // --- НОВАЯ ЛОГИКА ---
        // Мы проверяем квадрат вокруг точки (x, z). Если ХОТЯ БЫ ОДИН
        // соседний воксель в этом квадрате НЕ является проходимым полом
        // на ТОЙ ЖЕ ВЫСОТЕ, то мы считаем нашу точку (x,y,z) слишком
        // близкой к краю/стене/обрыву.
        for (int dz = -radiusInVoxels; dz <= radiusInVoxels; ++dz) {
          for (int dx = -radiusInVoxels; dx <= radiusInVoxels; ++dx) {
            int checkX = x + dx;
            int checkZ = z + dz;

            // Проверяем соседа на выход за границы мира
            if (checkX < 0 || checkX >= heightFilteredGrid.gridWidth ||
                checkZ < 0 || checkZ >= heightFilteredGrid.gridDepth) {
              canStandHere = false; // Сосед за границей, значит мы у края мира
              break;
            }

            // Получаем индекс соседа
            size_t neighborIndex =
                heightFilteredGrid.getVoxelIndex(checkX, y, checkZ);

            // Если соседний воксель НЕ является проходимым полом (из
            // предыдущего этапа)...
            if (!heightFilteredGrid.solidVoxels[neighborIndex]) {
              canStandHere = false; // ...значит мы уперлись в стену или обрыв
              break;
            }
          }
          if (!canStandHere)
            break;
        }

        if (canStandHere) {
          // Если после всех проверок мы все еще можем здесь стоять,
          // копируем 'true' в нашу финальную сетку.
          finalGrid.solidVoxels[currentIndex] = true;
        } else {
          removed_count++;
        }
      }
    }
  }

  qInfo(lcCore) << "Voxelizer: Radius filter complete. Initial walkable voxels:"
                << initial_count << ", removed:" << removed_count
                << ", final:" << (initial_count - removed_count);
  return finalGrid;
}