#pragma once

#include "Voxelizer.h" // Нам нужна структура VoxelGrid
#include <cstdint>     // Для uint8_t
#include <vector>

/**
 * @class VoxelCoster
 * @brief Утилитарный класс для назначения стоимостей проходимым вокселям.
 * @details Его основная задача - взять бинарную карту проходимости (да/нет)
 *          и превратить ее в карту стоимостей, которая учитывает такие факторы,
 *          как близость к обрывам. Это позволяет A* строить более безопасные
 *          пути.
 */
class VoxelCoster {
public:
  /**
   * @brief Анализирует готовую воксельную сетку и вычисляет стоимость прохода.
   * @param walkableGrid Финальная сетка проходимых вокселей из Voxelizer'а.
   * @param agentMaxClimbInVoxels Максимальный подъем агента в вокселях для
   * умной проверки обрывов.
   * @return Вектор `uint8_t` со стоимостями. 0 - непроходим.
   */
  static std::vector<uint8_t> calculateCosts(const VoxelGrid &walkableGrid,
                                             int agentMaxClimbInVoxels);
};