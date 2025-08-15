#pragma once

#include "core/generator/pipeline/Voxelizer.h"
#include "core/loader/ObjLoader.h"
#include "core/math/Types.h"
#include <functional>
#include <map> // Используем для хранения отладочных сеток
#include <string>
#include <vector>

/**
 * @struct NavMeshConfig
 * @brief Конфигурация для генератора навигационной сетки.
 */
struct NavMeshConfig {
  double cellSize = 0.3;
  double cellHeight = 0.2;
  double agentHeight = 2.0;
  double agentRadius = 0.6;
  double agentMaxClimb = 0.9;
  double agentMaxSlope = 45.0;
};

class NavMeshGenerator {
public:
  /**
   * @enum VoxelizationStage
   * @brief Перечисление этапов вокселизации для отладочной визуализации.
   */
  enum class VoxelizationStage {
    Solid,          ///< Этап 1: Вся "твердая" геометрия.
    WalkableFloors, ///< Этап 2: Потенциальные полы (воздух над полом).
    HeightFiltered, ///< Этап 3: Полы, прошедшие фильтр по высоте.
    FinalWalkable   ///< Этап 4: Финальный результат после фильтра по радиусу.
  };

  using ProgressCallback = std::function<void(int)>;
  explicit NavMeshGenerator(const NavMeshConfig &config);
  bool build(const MeshData &meshData,
             const ProgressCallback &progressCallback = nullptr);

  // --- Утилиты для 3D-поиска ---
  bool isWalkable(int x, int y, int z) const;
  bool worldToGrid(const Vector3d &worldPos, int &gridX, int &gridY,
                   int &gridZ) const;
  Vector3d gridToWorld(int gridX, int gridY, int gridZ) const;
  bool findClosestWalkableVoxel(const Vector3d &worldPos, int &outX, int &outY,
                                int &outZ) const;

  // --- Методы для визуализации ---
  const VoxelGrid &getVoxelGrid() const { return m_finalVoxelGrid; }

  /**
   * @brief Получает воксельную сетку определенного этапа для отладки.
   * @param stage Этап, сетку которого нужно получить.
   * @return Константная ссылка на запрошенную VoxelGrid.
   */
  const VoxelGrid &getDebugVoxelGrid(VoxelizationStage stage) const;

private:
  void calculateBounds(const std::vector<Vector3d> &vertices);

  NavMeshConfig m_config;
  Vector3d m_boundsMin;
  Vector3d m_boundsMax;

  /// @brief Финальная проходимая сетка, используемая для поиска пути.
  VoxelGrid m_finalVoxelGrid;

  /// @brief Карта для хранения промежуточных сеток для отладочной визуализации.
  std::map<VoxelizationStage, VoxelGrid> m_debugGrids;
};