#include "MeshFilter.h"
#include "shared/Logger.h"
#include <cmath> // Для acos и M_PI

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

MeshData MeshFilter::filterBySlope(const MeshData &inputMesh, double maxSlope) {
  qInfo(lcCore) << "Filtering mesh by slope. Max angle:" << maxSlope
                << "degrees.";

  MeshData filteredMesh;
  if (inputMesh.indices.empty()) {
    qWarning(lcCore) << "Input mesh has no indices to filter.";
    return filteredMesh;
  }

  // Резервируем память, предполагая, что большинство полигонов останется.
  // Это предотвратит многократные реаллокации векторов.
  filteredMesh.vertices = inputMesh.vertices; // Пока копируем все вершины
  filteredMesh.indices.reserve(inputMesh.indices.size());

  // Вектор "вверх" в мировой системе координат.
  // В нашем случае Z - это высота.
  const Vector3d upVector(0.0, 0.0, 1.0);

  // Переводим градусы в косинус угла для более быстрых вычислений.
  // Чем более пологий склон, тем ближе его нормаль к вектору "вверх",
  // и тем ближе косинус угла между ними к 1.0.
  const double maxSlopeRad = maxSlope * M_PI / 180.0;
  const double minDotProduct = cos(maxSlopeRad);

  int triangles_removed = 0;

  // Проходим по каждому треугольнику
  for (const auto &triangleIndices : inputMesh.indices) {
    // Получаем вершины треугольника
    const Vector3d &v0 = inputMesh.vertices[triangleIndices[0]];
    const Vector3d &v1 = inputMesh.vertices[triangleIndices[1]];
    const Vector3d &v2 = inputMesh.vertices[triangleIndices[2]];

    // Вычисляем два ребра треугольника
    const Vector3d edge1 = v1 - v0;
    const Vector3d edge2 = v2 - v0;

    // Вычисляем нормаль через векторное произведение.
    // Нормализуем ее, чтобы длина стала равна 1.
    Vector3d normal = edge1.cross(edge2);
    normal.normalize();

    // Скалярное произведение нормализованных векторов равно косинусу угла
    // между ними. Берем abs(), чтобы не волноваться о направлении нормали
    // (вверх или вниз).
    const double dotProduct = std::abs(normal.dot(upVector));

    // Если косинус больше нашего порога (т.е. угол меньше maxSlope),
    // то этот треугольник нам подходит.
    if (dotProduct >= minDotProduct) {
      filteredMesh.indices.push_back(triangleIndices);
    } else {
      triangles_removed++;
    }
  }

  // TODO: Оптимизация - удалить неиспользуемые вершины из
  // filteredMesh.vertices.
  //       Пока что это не критично, но в будущем может сэкономить память.

  qInfo(lcCore) << "Slope filter complete. Triangles kept:"
                << filteredMesh.indices.size()
                << ", removed:" << triangles_removed;

  return filteredMesh;
}