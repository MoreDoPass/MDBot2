#pragma once

#include "core/generator/pipeline/VoxelCoster.h"
#include "core/generator/pipeline/Voxelizer.h"
#include "core/loader/ObjLoader.h"
#include "core/math/Types.h"
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

// Forward declaration
class MeshFilter; // <-- Добавим, т.к. используем его в .cpp

struct NavMeshConfig {
  double cellSize = 0.3;
  double cellHeight = 0.2;
  double agentHeight = 2.0;
  double agentRadius = 0.6;
  double agentMaxClimb = 0.8; // <-- Увеличим значение по умолчанию
  double agentMaxSlope = 45.0;
};

class NavMeshGenerator {
public:
  enum class VoxelizationStage {
    Solid,
    WalkableFloors,
    HeightFiltered,
    RadiusFiltered, // <-- Добавим новое для отладки
    FinalWalkable // Этот оставим для совместимости, но он будет равен
                  // RadiusFiltered
  };

  using ProgressCallback = std::function<void(int)>;
  explicit NavMeshGenerator(const NavMeshConfig &config);
  bool build(const MeshData &meshData,
             const ProgressCallback &progressCallback = nullptr);

  // --- Новые публичные методы ---
  bool raycast(const Vector3d &start, const Vector3d &end) const;
  bool isSolid(int x, int y, int z) const; // Проверка для рейкаста

  // --- Утилиты для 3D-поиска (обновлены) ---
  bool isWalkable(int x, int y, int z) const;
  uint8_t getVoxelCost(int x, int y, int z) const;
  bool worldToGrid(const Vector3d &worldPos, int &gridX, int &gridY,
                   int &gridZ) const;
  Vector3d gridToWorld(int gridX, int gridY, int gridZ) const;
  bool findClosestWalkableVoxel(const Vector3d &worldPos, int &outX, int &outY,
                                int &outZ) const;

  // --- Методы для визуализации и доступа ---
  const std::vector<uint8_t> &getVoxelCosts() const { return m_voxelCosts; }
  const VoxelGrid &getDebugVoxelGrid(VoxelizationStage stage) const;
  const VoxelGrid &getSolidGrid() const { return m_solidGrid; }

  // --- Методы для получения размеров сетки ---
  int getGridWidth() const { return m_gridWidth; }
  int getGridHeight() const { return m_gridHeight; }
  int getGridDepth() const { return m_gridDepth; }

private:
  void calculateBounds(const std::vector<Vector3d> &vertices);

  NavMeshConfig m_config;
  Vector3d m_boundsMin;
  Vector3d m_boundsMax;

  int m_gridWidth = 0;
  int m_gridHeight = 0;
  int m_gridDepth = 0;

  /// @brief Карта всех препятствий для рейкастинга.
  VoxelGrid m_solidGrid;

  /// @brief Финальная карта стоимостей для поиска пути.
  std::vector<uint8_t> m_voxelCosts;

  /// @brief Карта для хранения промежуточных сеток для отладочной визуализации.
  std::map<VoxelizationStage, VoxelGrid> m_debugGrids;
};