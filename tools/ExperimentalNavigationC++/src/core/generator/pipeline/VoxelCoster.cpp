#include "VoxelCoster.h"
#include "shared/Logger.h"

// Реализация нашего статического метода
std::vector<uint8_t> VoxelCoster::calculateCosts(const VoxelGrid &walkableGrid,
                                                 int agentMaxClimbInVoxels) {

  qInfo(lcCore)
      << "Calculating voxel costs with SLOPE-AWARE cliff detection...";

  if (walkableGrid.solidVoxels.empty()) {
    qWarning(lcCore) << "Cannot calculate costs, input walkableGrid is empty.";
    return {};
  }

  // Создаем вектор для стоимостей, изначально все непроходимо (0)
  std::vector<uint8_t> costs(walkableGrid.solidVoxels.size(), 0);
  const int gridWidth = walkableGrid.gridWidth;
  const int gridHeight = walkableGrid.gridHeight;
  const int gridDepth = walkableGrid.gridDepth;

  // Глубина проверки падения вниз. Должна быть больше, чем высота подъема.
  const int cliffCheckFallDown = agentMaxClimbInVoxels + 2;

  // Проходим по всем вокселям сетки
  for (int y = 0; y < gridHeight; ++y) {
    for (int z = 0; z < gridDepth; ++z) {
      for (int x = 0; x < gridWidth; ++x) {

        const size_t currentIndex = walkableGrid.getVoxelIndex(x, y, z);

        // Работаем только с проходимыми вокселями
        if (!walkableGrid.solidVoxels[currentIndex]) {
          continue;
        }

        uint16_t currentCost = 1; // Базовая стоимость для проходимого вокселя

        // Проверяем 8 соседей по горизонтали
        for (int dz = -1; dz <= 1; ++dz) {
          for (int dx = -1; dx <= 1; ++dx) {
            if (dx == 0 && dz == 0)
              continue; // Пропускаем самого себя

            int checkX = x + dx;
            int checkZ = z + dz;

            // Если сосед за пределами карты, считаем это небольшим обрывом
            if (checkX < 0 || checkX >= gridWidth || checkZ < 0 ||
                checkZ >= gridDepth) {
              currentCost += 2;
              continue;
            }

            // --- ГЛАВНОЕ ИЗМЕНЕНИЕ: УМНАЯ ПРОВЕРКА ОПОРЫ У СОСЕДА ---
            bool isNeighborSafe = false;
            // Ищем опору для соседа в вертикальном диапазоне, который может
            // преодолеть агент
            for (int dy = -agentMaxClimbInVoxels; dy <= agentMaxClimbInVoxels;
                 ++dy) {
              int checkY = y + dy;
              // Проверяем, что не вышли за пределы по высоте
              if (checkY >= 0 && checkY < gridHeight) {
                // Если нашли в этой колонке проходимый воксель, значит это
                // склон/ступенька, а не обрыв
                if (walkableGrid.solidVoxels[walkableGrid.getVoxelIndex(
                        checkX, checkY, checkZ)]) {
                  isNeighborSafe = true;
                  break; // Нашли безопасную опору, дальше в этой колонке не
                         // ищем
                }
              }
            }

            // Если мы нашли опору (isNeighborSafe == true), значит сосед
            // безопасен. Переходим к следующему соседу.
            if (isNeighborSafe) {
              continue;
            }

            // Если мы дошли сюда, значит безопасной опоры для соседа рядом не
            // нашлось. Это может быть обрыв. Проверим, есть ли земля далеко
            // внизу.
            bool isGroundFoundFarBelow = false;
            for (int i = 1; i <= cliffCheckFallDown; ++i) {
              int checkY = y - i;
              if (checkY < 0)
                break;

              if (walkableGrid.solidVoxels[walkableGrid.getVoxelIndex(
                      checkX, checkY, checkZ)]) {
                isGroundFoundFarBelow = true;
                break;
              }
            }

            // Если земли нет даже далеко внизу, это точно обрыв. Увеличиваем
            // стоимость.
            if (!isGroundFoundFarBelow) {
              currentCost += 4; // Штраф за обрыв
            }
          }
        }

        // Записываем финальную стоимость, ограничивая сверху (255 - спец.
        // значение для A*)
        costs[currentIndex] =
            static_cast<uint8_t>(std::min(currentCost, (uint16_t)254));
      }
    }
  }

  qInfo(lcCore) << "Voxel cost calculation complete.";
  return costs;
}