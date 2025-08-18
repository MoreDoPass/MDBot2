#pragma once

#include "core/loader/ObjLoader.h"
#include "core/math/Types.h"
#include <vector>

// Структура VoxelGrid остается без изменений
struct VoxelGrid {
  std::vector<bool> solidVoxels;
  int gridWidth = 0;
  int gridHeight = 0;
  int gridDepth = 0;

  size_t getVoxelIndex(int x, int y, int z) const {
    return (size_t)x + (size_t)z * gridWidth +
           (size_t)y * gridWidth * gridDepth;
  }
};

/**
 * @class Voxelizer
 * @brief Набор статических инструментов для создания и обработки воксельных
 * сеток.
 */
class Voxelizer {
public:
  /**
   * @brief ЭТАП 1: Создает "сырую" 3D-карту ВСЕЙ геометрии.
   * @details Растеризует ВСЕ треугольники (включая стены и препятствия) в
   * VoxelGrid. true - геометрия, false - воздух.
   * @return VoxelGrid с "твердыми" вокселями.
   */
  static VoxelGrid createSolidVoxels(const MeshData &meshData, double cellSize,
                                     double cellHeight,
                                     const Vector3d &boundsMin,
                                     const Vector3d &boundsMax);

  /**
   * @brief ЭТАП 2: Находит все проходимые полы с учетом высоты подъема.
   * @param solidGrid Карта "твердых" вокселей, результат Этапа 1.
   * @param agentMaxClimb Максимальная высота, на которую может подняться агент.
   * @param cellHeight Высота одного вокселя.
   * @return Новая VoxelGrid, где создан сплошной проходимый слой над всей
   * "землей".
   */
  static VoxelGrid filterWalkableFloors(const VoxelGrid &solidGrid,
                                        double agentMaxClimb,
                                        double cellHeight);

  /**
   * @brief ЭТАП 3: Фильтрует полы по высоте агента.
   * @param walkableFloors Карта полов, результат Этапа 2.
   * @param solidGrid Карта стен/потолков из Этапа 1 (нужна для проверки
   * клиренса).
   * @param agentHeight Высота агента в мировых единицах.
   * @param cellHeight Высота одного вокселя.
   * @return Новая VoxelGrid, где остались только те полы, над которыми
   * достаточно места.
   */
  static VoxelGrid filterByAgentHeight(const VoxelGrid &walkableFloors,
                                       const VoxelGrid &solidGrid,
                                       double agentHeight, double cellHeight);

  /**
   * @brief ЭТАП 4: Фильтрует проходимые воксели по радиусу агента.
   * @details "Стирает" те проходимые воксели, которые находятся слишком близко
   * к стенам или препятствиям.
   * @param heightFilteredGrid Карта полов, прошедшая фильтр по высоте
   * (результат Этапа 3).
   * @param solidGrid Карта стен/потолков из Этапа 1 (нужна для проверки
   * столкновений).
   * @param agentRadius Радиус агента в мировых единицах.
   * @param cellSize Размер вокселя по X/Z.
   * @return Финальная VoxelGrid, готовая для поиска пути.
   */
  static VoxelGrid filterByAgentRadius(const VoxelGrid &heightFilteredGrid,
                                       const VoxelGrid &solidGrid,
                                       double agentRadius, double cellSize);
};