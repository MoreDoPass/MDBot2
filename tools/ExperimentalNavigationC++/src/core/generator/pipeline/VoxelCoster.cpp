#include "VoxelCoster.h"
#include "shared/Logger.h"

// Реализация нашего статического метода
std::vector<uint8_t> VoxelCoster::calculateCosts(const VoxelGrid &walkableGrid,
                                                 const VoxelGrid &solidGrid) {
  qInfo(lcCore) << "Calculating voxel costs with improved cliff detection...";

  if (walkableGrid.solidVoxels.empty() || solidGrid.solidVoxels.empty()) {
    qWarning(lcCore) << "Cannot calculate costs, input voxel grids are empty.";
    return {};
  }

  std::vector<uint8_t> costs(walkableGrid.solidVoxels.size(), 0);
  const int gridWidth = walkableGrid.gridWidth;
  const int gridHeight = walkableGrid.gridHeight;
  const int gridDepth = walkableGrid.gridDepth;

  // --- ИЗМЕНЕНИЕ: Определяем глубину проверки на обрыв ---
  // Сколько вокселей вниз мы будем проверять, прежде чем признать это обрывом.
  // 3 вокселя - хороший компромисс.
  const int cliffCheckDepth = 3;

  for (int y = 0; y < gridHeight; ++y) {
    for (int z = 0; z < gridDepth; ++z) {
      for (int x = 0; x < gridWidth; ++x) {

        const size_t currentIndex = walkableGrid.getVoxelIndex(x, y, z);

        if (!walkableGrid.solidVoxels[currentIndex]) {
          continue;
        }

        uint16_t currentCost = 1;

        for (int dz = -1; dz <= 1; ++dz) {
          for (int dx = -1; dx <= 1; ++dx) {
            if (dx == 0 && dz == 0)
              continue;

            int checkX = x + dx;
            int checkZ = z + dz;

            // Проверка на выход за пределы карты (это всегда обрыв)
            if (checkX < 0 || checkX >= gridWidth || checkZ < 0 ||
                checkZ >= gridDepth) {
              currentCost += 5;
              continue;
            }

            const size_t neighborIndex =
                walkableGrid.getVoxelIndex(checkX, y, checkZ);

            // Если соседний воксель на том же уровне - проходимый, то все ОК.
            if (walkableGrid.solidVoxels[neighborIndex]) {
              continue;
            }

            // --- НОВАЯ УМНАЯ ЛОГИКА ПРОВЕРКИ ОБРЫВА ---
            // Сосед непроходим. Теперь проверим, склон это или реальный обрыв.
            bool isGroundFound = false;
            for (int i = 1; i <= cliffCheckDepth; ++i) {
              int checkY = y - i;
              if (checkY < 0)
                break; // Дошли до дна карты

              size_t neighborBelowIndex =
                  solidGrid.getVoxelIndex(checkX, checkY, checkZ);
              if (solidGrid.solidVoxels[neighborBelowIndex]) {
                isGroundFound = true; // Нашли опору! Это склон/ступенька.
                break;
              }
            }

            // Если мы просканировали всю глубину и не нашли опоры - это обрыв.
            if (!isGroundFound) {
              currentCost += 5; // Добавляем штраф
            }
          }
        }

        if (currentCost > 254) {
          currentCost = 254;
        }
        costs[currentIndex] = static_cast<uint8_t>(currentCost);
      }
    }
  }

  qInfo(lcCore) << "Voxel cost calculation complete.";
  return costs;
}