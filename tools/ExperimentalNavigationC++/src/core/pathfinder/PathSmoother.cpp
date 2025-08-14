#include "PathSmoother.h"
#include "shared/Logger.h"

#include <vtkCellLocator.h>
#include <vtkIdList.h>
#include <vtkNew.h>
#include <vtkPolyData.h>

PathSmoother::PathSmoother(vtkPolyData *collisionMesh) {
  m_collisionLocator = vtkSmartPointer<vtkCellLocator>::New();
  m_collisionLocator->SetDataSet(collisionMesh);
  m_collisionLocator->BuildLocator();
}

bool PathSmoother::hasLineOfSight(const Vector3d &start, const Vector3d &end) {
  // Создаем небольшой отступ от поверхностей, чтобы луч не пересек "пол" или
  // "потолок"
  Vector3d adjustedStart = start + Vector3d(0, 0, 0.2);
  Vector3d adjustedEnd = end + Vector3d(0, 0, 0.2);

  // IntersectWithLine возвращает 0, если пересечений НЕТ, и не-ноль, если ЕСТЬ.
  // Поэтому мы возвращаем результат сравнения с нулем.
  return m_collisionLocator->IntersectWithLine(adjustedStart.data(),
                                               adjustedEnd.data(), 0, nullptr,
                                               nullptr) == 0;
}

std::vector<Vector3d>
PathSmoother::smoothPath(const std::vector<Vector3d> &pathPoints) {
  // Если в пути меньше 3-х точек, сглаживать нечего.
  if (pathPoints.size() < 3) {
    return pathPoints;
  }

  std::vector<Vector3d> smoothedPath;
  smoothedPath.push_back(pathPoints.front()); // Начальная точка всегда в пути

  auto currentPointIt = pathPoints.begin();

  // Идем по пути, пока не дойдем до предпоследней точки
  while (currentPointIt != pathPoints.end() - 1) {
    // Начинаем проверку со следующей точки
    auto bestVisibleIt = currentPointIt + 1;

    // Пытаемся "дотянуться" до самых дальних точек в оставшейся части пути
    for (auto testPointIt = pathPoints.end() - 1; testPointIt > bestVisibleIt;
         --testPointIt) {
      // Если из текущей точки мы видим тестовую точку...
      if (hasLineOfSight(*currentPointIt, *testPointIt)) {
        // ...то это наш новый лучший кандидат.
        bestVisibleIt = testPointIt;
        break; // Дальше проверять нет смысла, мы нашли самую дальнюю видимую
               // точку
      }
    }
    // Добавляем лучшую найденную точку в сглаженный путь
    smoothedPath.push_back(*bestVisibleIt);
    // И начинаем новый поиск уже с нее
    currentPointIt = bestVisibleIt;
  }

  qInfo(lcCore) << "Path smoothed from" << pathPoints.size() << "to"
                << smoothedPath.size() << "points.";
  return smoothedPath;
}