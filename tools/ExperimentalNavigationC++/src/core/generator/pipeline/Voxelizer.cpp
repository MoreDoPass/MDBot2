#include "Voxelizer.h"
#include "AabbTriangleIntersection.h" // <-- НАШ НОВЫЙ ИНСТРУМЕНТ
#include "shared/Logger.h"
#include <algorithm> // Для std::min/max
#include <cmath>

#include <numeric> // <-- Для std::iota, чтобы создать индексы
#include <thread>  // <-- ДЛЯ МНОГОПОТОЧНОСТИ
#include <vector>  // <-- ДЛЯ МНОГОПОТОЧНОСТИ

VoxelGrid Voxelizer::createSolidVoxels(const MeshData &meshData,
                                       double cellSize, double cellHeight,
                                       const Vector3d &boundsMin,
                                       const Vector3d &boundsMax) {
  qInfo(lcCore) << "Voxelizer: Starting FAST solid voxel creation...";

  // --- ШАГ 1: Подготовка сетки (без изменений) ---
  VoxelGrid grid;
  grid.gridWidth =
      static_cast<int>(ceil((boundsMax.x() - boundsMin.x()) / cellSize));
  grid.gridDepth =
      static_cast<int>(ceil((boundsMax.y() - boundsMin.y()) / cellSize));
  grid.gridHeight =
      static_cast<int>(ceil((boundsMax.z() - boundsMin.z()) / cellHeight));

  if (grid.gridWidth == 0 || grid.gridHeight == 0 || grid.gridDepth == 0) {
    qWarning(lcCore) << "Voxel grid has zero dimension. Aborting.";
    return grid;
  }

  const size_t totalVoxels =
      (size_t)grid.gridWidth * grid.gridHeight * grid.gridDepth;
  grid.solidVoxels.assign(totalVoxels, false);

  const int numTriangles = meshData.indices.size();
  if (numTriangles == 0) {
    qWarning(lcCore) << "Mesh has no triangles to voxelize.";
    return grid;
  }

  // --- ШАГ 2: Подготовка потоков (без изменений) ---
  const unsigned int numThreads = std::max(
      1u, std::thread::hardware_concurrency()); // Используем все доступные ядра
  qInfo(lcCore) << "Using" << numThreads << "threads for voxelization.";

  std::vector<std::thread> threads;
  threads.reserve(numThreads);

  // --- ИЗМЕНЕНИЕ ---
  // Вместо вектора VoxelGrid, теперь мы храним вектор векторов с индексами.
  // Каждый поток будет складывать сюда ИНДЕКСЫ вокселей, которые нужно
  // закрасить.
  std::vector<std::vector<size_t>> localResultIndices(numThreads);

  const int trianglesPerThread = (numTriangles + numThreads - 1) / numThreads;

  // --- ШАГ 3: Запуск потоков с новой логикой ---
  for (unsigned int i = 0; i < numThreads; ++i) {

    const int startTriangle = i * trianglesPerThread;
    const int endTriangle =
        std::min(startTriangle + trianglesPerThread, numTriangles);

    // Запускаем поток
    threads.emplace_back([&, startTriangle, endTriangle, i] {
      // Локальный вектор для индексов этого потока.
      std::vector<size_t> indicesForThisThread;
      // Предварительно резервируем память, чтобы избежать частых реаллокаций
      indicesForThisThread.reserve(numTriangles * 10);

      // Временная сетка для отслеживания уже добавленных вокселей ВНУТРИ ОДНОГО
      // ПОТОКА Это нужно, чтобы один и тот же воксель не был добавлен в список
      // индексов много раз, если в него попадает несколько треугольников из
      // одной "пачки".
      VoxelGrid localTrackerGrid;
      localTrackerGrid.gridWidth = grid.gridWidth;
      localTrackerGrid.gridHeight = grid.gridHeight;
      localTrackerGrid.gridDepth = grid.gridDepth;
      localTrackerGrid.solidVoxels.assign(totalVoxels, false);

      const float cs = static_cast<float>(cellSize);
      const float ch = static_cast<float>(cellHeight);
      const float ics = 1.0f / cs;
      const float ich = 1.0f / ch;
      const Vector3f box_halfsize(cs * 0.5f, cs * 0.5f, ch * 0.5f);

      for (int triIdx = startTriangle; triIdx < endTriangle; ++triIdx) {
        const auto &tri_indices = meshData.indices[triIdx];

        Vector3f tri_verts[3] = {
            meshData.vertices[tri_indices[0]].cast<float>(),
            meshData.vertices[tri_indices[1]].cast<float>(),
            meshData.vertices[tri_indices[2]].cast<float>()};

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
        int Imin_z = static_cast<int>(floor((min_y - boundsMin.y()) * ics));
        int Imax_z = static_cast<int>(ceil((max_y - boundsMin.y()) * ics));
        int Imin_y = static_cast<int>(floor((min_z - boundsMin.z()) * ich));
        int Imax_y = static_cast<int>(ceil((max_z - boundsMin.z()) * ich));

        for (int iy = Imin_y; iy <= Imax_y; ++iy) {
          for (int iz = Imin_z; iz <= Imax_z; ++iz) {
            for (int ix = Imin_x; ix <= Imax_x; ++ix) {
              if (ix < 0 || ix >= grid.gridWidth || iy < 0 ||
                  iy >= grid.gridHeight || iz < 0 || iz >= grid.gridDepth) {
                continue;
              }

              size_t index = localTrackerGrid.getVoxelIndex(ix, iy, iz);
              if (localTrackerGrid.solidVoxels[index]) {
                continue;
              }

              Vector3f box_center(boundsMin.x() + (ix + 0.5f) * cs,
                                  boundsMin.y() + (iz + 0.5f) * cs,
                                  boundsMin.z() + (iy + 0.5f) * ch);

              if (Intersection::triBoxOverlap(box_center, box_halfsize,
                                              tri_verts)) {
                // Вместо записи в локальную сетку, мы добавляем ИНДЕКС в список
                indicesForThisThread.push_back(index);
                localTrackerGrid.solidVoxels[index] =
                    true; // И помечаем, что мы его уже добавили
              }
            }
          }
        }
      }
      // В конце работы поток сохраняет свой список индексов в общий массив
      // результатов.
      localResultIndices[i] = std::move(indicesForThisThread);
    });
  }

  // --- ШАГ 4: Дожидаемся завершения ВСЕХ потоков ---
  for (auto &t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }
  qInfo(lcCore) << "All threads finished processing triangles.";

  // --- ШАГ 5: Слияние результатов (МОЛНИЕНОСНАЯ ВЕРСИЯ) ---
  qInfo(lcCore) << "Merging results from all threads (index-based)...";

  long long solid_count = 0;
  // Проходим по вектору результатов КАЖДОГО потока
  for (const auto &index_list : localResultIndices) {
    // Проходим по списку ИНДЕКСОВ, которые нашел этот поток
    for (size_t index : index_list) {
      // Если этот воксель еще не был закрашен
      if (!grid.solidVoxels[index]) {
        // Закрашиваем его
        grid.solidVoxels[index] = true;
        solid_count++;
      }
    }
  }

  qInfo(lcCore) << "Voxelizer: Accurate solid voxelization complete. Found"
                << solid_count << "solid voxels.";
  return grid;
}

// --- ВОЗВРАЩАЕМ ПРОСТУЮ, НАДЕЖНУЮ ОДНОПОТОЧНУЮ ВЕРСИЮ ---
VoxelGrid Voxelizer::filterWalkableFloors(const VoxelGrid &solidGrid) {
  qInfo(lcCore) << "Voxelizer: Filtering walkable floors (single-threaded, "
                   "cache-efficient)...";

  // Создаем новую сетку для результатов, копируя размеры из исходной.
  VoxelGrid walkableGrid = solidGrid;
  if (solidGrid.solidVoxels.empty()) {
    qWarning(lcCore) << "Input solidGrid is empty, skipping floor filter.";
    return walkableGrid;
  }
  // Заполняем ее 'false', чтобы начать с чистого листа.
  walkableGrid.solidVoxels.assign(solidGrid.solidVoxels.size(), false);

  long long walkable_count = 0;
  // Начинаем с Y=1, так как для каждого вокселя мы смотрим на воксель ПОД ним
  // (y-1).
  for (int y = 1; y < solidGrid.gridHeight; ++y) {
    for (int z = 0; z < solidGrid.gridDepth; ++z) {
      for (int x = 0; x < solidGrid.gridWidth; ++x) {

        const size_t currentIndex = solidGrid.getVoxelIndex(x, y, z);
        const size_t floorIndex = solidGrid.getVoxelIndex(x, y - 1, z);

        // Главное условие: если текущий воксель - это воздух,
        // а воксель под ним - твердый...
        if (!solidGrid.solidVoxels[currentIndex] &&
            solidGrid.solidVoxels[floorIndex]) {

          // ...то помечаем текущий воксель как проходимый пол.
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

// --- ВОЗВРАЩАЕМ ПРОСТУЮ, НАДЕЖНУЮ ОДНОПОТОЧНУЮ ВЕРСИЮ ---
VoxelGrid Voxelizer::filterByAgentHeight(const VoxelGrid &walkableFloors,
                                         const VoxelGrid &solidGrid,
                                         double agentHeight,
                                         double cellHeight) {
  qInfo(lcCore) << "Voxelizer: Filtering by agent height (single-threaded)...";
  VoxelGrid finalGrid = walkableFloors;
  if (walkableFloors.solidVoxels.empty())
    return finalGrid;

  const int heightInVoxels = static_cast<int>(ceil(agentHeight / cellHeight));

  for (int y = 0; y < finalGrid.gridHeight; ++y) {
    for (int z = 0; z < finalGrid.gridDepth; ++z) {
      for (int x = 0; x < finalGrid.gridWidth; ++x) {
        size_t currentIndex = finalGrid.getVoxelIndex(x, y, z);
        if (finalGrid.solidVoxels[currentIndex]) {
          for (int h = 1; h < heightInVoxels; ++h) {
            int checkY = y + h;
            if (checkY >= solidGrid.gridHeight)
              break;

            if (solidGrid.solidVoxels[solidGrid.getVoxelIndex(x, checkY, z)]) {
              finalGrid.solidVoxels[currentIndex] = false;
              break;
            }
          }
        }
      }
    }
  }

  long long final_count = 0;
  for (bool v : finalGrid.solidVoxels)
    if (v)
      final_count++;
  qInfo(lcCore) << "Voxelizer: Height filter complete. Final walkable voxels:"
                << final_count;
  return finalGrid;
}

// --- ВОЗВРАЩАЕМ ПРОСТУЮ, НАДЕЖНУЮ ОДНОПОТОЧНУЮ ВЕРСИЮ ---
VoxelGrid Voxelizer::filterByAgentRadius(const VoxelGrid &heightFilteredGrid,
                                         const VoxelGrid &solidGrid,
                                         double agentRadius, double cellSize) {
  qInfo(lcCore) << "Voxelizer: Eroding walkable area with slope detection...";

  VoxelGrid finalGrid = heightFilteredGrid;
  finalGrid.solidVoxels.assign(finalGrid.solidVoxels.size(), false);

  if (heightFilteredGrid.solidVoxels.empty()) {
    qWarning(lcCore) << "Input grid for radius filter is empty. Skipping.";
    return finalGrid;
  }

  const int radiusInVoxels = static_cast<int>(ceil(agentRadius / cellSize));
  qInfo(lcCore) << "Agent radius" << agentRadius << "maps to" << radiusInVoxels
                << "voxels for erosion.";

  for (int y = 0; y < heightFilteredGrid.gridHeight; ++y) {
    for (int z = 0; z < heightFilteredGrid.gridDepth; ++z) {
      for (int x = 0; x < heightFilteredGrid.gridWidth; ++x) {

        if (!heightFilteredGrid
                 .solidVoxels[heightFilteredGrid.getVoxelIndex(x, y, z)]) {
          continue;
        }

        bool isSafe = true;
        for (int dz = -radiusInVoxels; dz <= radiusInVoxels; ++dz) {
          for (int dx = -radiusInVoxels; dx <= radiusInVoxels; ++dx) {

            int checkX = x + dx;
            int checkZ = z + dz;

            if (checkX < 0 || checkX >= heightFilteredGrid.gridWidth ||
                checkZ < 0 || checkZ >= heightFilteredGrid.gridDepth) {
              isSafe = false;
              break;
            }

            // --- НОВАЯ УМНАЯ ПРОВЕРКА ---
            // Сосед считается препятствием, только если он непроходим
            // и под ним тоже нет проходимого пола (т.е. это не ступенька вниз).
            size_t neighborIndex =
                heightFilteredGrid.getVoxelIndex(checkX, y, checkZ);

            if (!heightFilteredGrid.solidVoxels[neighborIndex]) {
              // Сосед на нашем уровне непроходим. Но может это склон?
              // Проверим уровень ниже.
              if (y > 0) {
                size_t neighborBelowIndex =
                    heightFilteredGrid.getVoxelIndex(checkX, y - 1, checkZ);
                // Если и на уровень ниже пусто, то это точно стена/обрыв.
                if (!heightFilteredGrid.solidVoxels[neighborBelowIndex]) {
                  isSafe = false;
                  break;
                }
                // Если мы здесь, значит под соседом есть земля. Это склон.
                // Не считаем это препятствием для эрозии.
              } else {
                // Мы на самом нижнем уровне, и сосед непроходим. Это стена.
                isSafe = false;
                break;
              }
            }
          }
          if (!isSafe)
            break;
        }

        if (isSafe) {
          finalGrid.solidVoxels[finalGrid.getVoxelIndex(x, y, z)] = true;
        }
      }
    }
  }

  long long final_count = 0;
  for (bool v : finalGrid.solidVoxels)
    if (v)
      final_count++;
  qInfo(lcCore) << "Voxelizer: Radius filter (erosion) complete. Final "
                   "walkable voxels:"
                << final_count;
  return finalGrid;
}