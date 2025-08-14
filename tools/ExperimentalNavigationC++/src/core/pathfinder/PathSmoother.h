#pragma once

#include "../math/Types.h"
#include <vector>
#include <vtkSmartPointer.h>

// Прямые объявления
class vtkPolyData;
class vtkCellLocator;

/**
 * @class PathSmoother
 * @brief Отвечает за сглаживание "сырого" пути, полученного от A*.
 * @details Убирает лишние точки из пути, проверяя прямую видимость (без
 * столкновений) между узлами.
 */
class PathSmoother {
public:
  /**
   * @brief Конструктор.
   * @param collisionMesh Указатель на сырой меш мира, который будет
   * использоваться для проверки столкновений.
   */
  explicit PathSmoother(vtkPolyData *collisionMesh);

  /**
   * @brief Сглаживает заданный путь.
   * @param pathPoints Вектор точек, представляющий "сырой" путь от A*.
   * @return Вектор точек, представляющий сглаженный, оптимизированный путь.
   */
  std::vector<Vector3d> smoothPath(const std::vector<Vector3d> &pathPoints);

private:
  /**
   * @brief Проверяет, есть ли прямая линия видимости между двумя точками.
   * @details Использует рейкастинг по `collisionMesh`.
   * @param start Начальная точка.
   * @param end Конечная точка.
   * @return true, если линия видимости есть (нет столкновений), иначе false.
   */
  bool hasLineOfSight(const Vector3d &start, const Vector3d &end);

  /// @brief Умный указатель на дерево для быстрой проверки столкновений.
  vtkSmartPointer<vtkCellLocator> m_collisionLocator;
};