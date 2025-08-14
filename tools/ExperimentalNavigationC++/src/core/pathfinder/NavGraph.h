#pragma once

#include "../math/Types.h"
#include <vector>
#include <vtkSmartPointer.h>

// Прямое объявление
class vtkPolyData;

// Объявляем удобный псевдоним для нашего списка смежности.
// Для каждого узла (с индексом i) мы будем хранить вектор ID его соседей.
using AdjacencyList = std::vector<std::vector<int>>;

/**
 * @class NavGraph
 * @brief Представляет навигационный граф, построенный по проходимому мешу.
 * @details Хранит узлы (центры полигонов) и связи между ними (список
 * смежности).
 */
class NavGraph {
public:
  NavGraph();

  /**
   * @brief Строит граф по отфильтрованному мешу проходимых полигонов.
   * @param walkablePolys Меш, содержащий ТОЛЬКО проходимые полигоны.
   * @param maxStepHeight Максимальная высота "шага" между центрами соседних
   * полигонов.
   */
  void build(vtkSmartPointer<vtkPolyData> walkablePolys, double maxStepHeight);

  /// @brief Возвращает список всех узлов (центров полигонов) в мировых
  /// координатах.
  const std::vector<Vector3d> &getNodes() const;

  /// @brief Возвращает граф в виде списка смежности.
  const AdjacencyList &getAdjacencyList() const;

private:
  /// @brief Вектор, хранящий 3D-координаты каждого узла (центра полигона).
  std::vector<Vector3d> m_nodes;

  /// @brief Список смежности. Индекс вектора - ID узла.
  AdjacencyList m_adj;
};