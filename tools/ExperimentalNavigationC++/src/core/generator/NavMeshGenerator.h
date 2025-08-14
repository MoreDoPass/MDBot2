#pragma once

#include "core/loader/ObjLoader.h"
#include "core/math/Types.h"
#include <functional>
#include <vector>

/**
 * @struct NavMeshConfig
 * @brief Структура для хранения всех параметров генерации NavMesh.
 */
struct NavMeshConfig {
  double cellSize = 0.3;       // Размер одного вокселя по XZ (ширина/длина)
  double cellHeight = 0.2;     // Размер одного вокселя по Y (высота)
  double agentHeight = 2.0;    // Высота персонажа
  double agentRadius = 0.6;    // Радиус персонажа
  double agentMaxClimb = 1.5;  // Максимальная высота, на которую может залезть
  double agentMaxSlope = 45.0; // Максимальный угол наклона поверхности

  // Добавим поля для размеров сетки
  int gridWidth = 0;
  int gridDepth = 0;
};

/**
 * @struct HeightfieldSpan
 * @brief Представляет один непрерывный проходимый "пролёт" в колонке вокселей.
 */
struct HeightfieldSpan {
  int min;          ///< Индекс вокселя-пола (включительно).
  int max;          ///< Индекс вокселя-потолка (включительно).
  int regionId = 0; ///< ID региона, к которому принадлежит (для будущих шагов).
};

/**
 * @class NavMeshGenerator
 * @brief Основной класс, отвечающий за создание навигационного меша.
 */
class NavMeshGenerator {
public:
  using ProgressCallback = std::function<void(int)>;

  explicit NavMeshGenerator(const NavMeshConfig &config);

  bool build(const MeshData &meshData,
             const ProgressCallback &progressCallback = nullptr);

  std::vector<Vector3d> getWalkableVoxelCenters() const;

  // Утилиты, которые нам понадобятся
  bool findClosestWalkableVoxel(const Vector3d &worldPos, int &gridX,
                                int &gridY, int &gridZ) const;
  Vector3d gridToWorld(int gridX, int gridY, int gridZ) const;
  bool isWalkable(int startX, int startZ, int startY_idx, int endX, int endZ,
                  int &endY_idx) const;
  const NavMeshConfig &getConfig() const { return m_config; }

private:
  void calculateBounds(const std::vector<Vector3d> &vertices);
  void createSolidVoxels(const MeshData &meshData,
                         const ProgressCallback &progressCallback);
  void buildHeightfield();
  bool worldToGrid(const Vector3d &worldPos, int &gridX, int &gridZ) const;

  NavMeshConfig m_config;
  Vector3d m_boundsMin;
  Vector3d m_boundsMax;

  int m_gridWidth = 0;
  int m_gridHeight = 0;
  int m_gridDepth = 0;

  std::vector<bool> m_solidVoxels;
  std::vector<std::vector<HeightfieldSpan>> m_heightfield;
};