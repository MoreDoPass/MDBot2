#pragma once

#include "core/math/Types.h"
#include <Eigen/Dense>
#include <algorithm>
#include <cmath>

// Используем float для производительности в тестах на пересечение
using Vector3f = Eigen::Vector3f;

/**
 * @file AabbTriangleIntersection.h
 * @brief Содержит реализацию теста на пересечение AABB (куба) и треугольника.
 * @details Используется алгоритм на основе Теоремы о разделяющей оси (SAT).
 *          Это стандартный и надежный способ для точных проверок пересечений.
 *          Вся математика инкапсулирована здесь, чтобы не загрязнять Voxelizer.
 */

namespace Intersection {

/**
 * @brief Проецирует вершины на ось и находит минимальное/максимальное значение.
 */
inline void find_min_max(float v0, float v1, float v2, float &min, float &max) {
  min = max = v0;
  if (v1 < min)
    min = v1;
  if (v1 > max)
    max = v1;
  if (v2 < min)
    min = v2;
  if (v2 > max)
    max = v2;
}

/**
 * @brief Основная функция, выполняющая тест на пересечение.
 * @param box_center Центр куба (вокселя).
 * @param box_halfsize Половинный размер куба (вокселя).
 * @param tri_verts Массив из 3-х вершин треугольника.
 * @return true, если есть пересечение, иначе false.
 */
inline bool
triBoxOverlap(const Vector3f &box_center,
              const Vector3f &box_halfsize_orig, // Переименовали для ясности
              const Vector3f tri_verts[3]) {

  // =================================================================================
  // === ГЛАВНЫЙ ФИКС ЗДЕСЬ ===
  // === Мы добавляем крошечную константу (эпсилон) к размерам куба. ===
  // === Это делает тест устойчивым к ошибкам округления, когда треугольник ===
  // === лежит ровно на границе вокселя. ===
  // =================================================================================
  const float EPSILON = 1e-5f;
  const Vector3f box_halfsize =
      box_halfsize_orig + Vector3f(EPSILON, EPSILON, EPSILON);

  // Перемещаем все в систему координат, где центр куба находится в (0,0,0)
  Vector3f v0 = tri_verts[0] - box_center;
  Vector3f v1 = tri_verts[1] - box_center;
  Vector3f v2 = tri_verts[2] - box_center;

  // Вычисляем ребра треугольника
  Vector3f e0 = v1 - v0;
  Vector3f e1 = v2 - v1;
  Vector3f e2 = v0 - v2;

  // --- Тестируем 9 осей, образованных векторным произведением ребер ---
  float min, max, p0, p1, p2, rad, fex, fey, fez;

#define AXISTEST_X(a, b, fa, fb)                                               \
  p0 = a * v0.y() - b * v0.z();                                                \
  p1 = a * v1.y() - b * v1.z();                                                \
  p2 = a * v2.y() - b * v2.z();                                                \
  rad = fa * box_halfsize.y() + fb * box_halfsize.z();                         \
  find_min_max(p0, p1, p2, min, max);                                          \
  if (min > rad || max < -rad)                                                 \
    return false;

#define AXISTEST_Y(a, b, fa, fb)                                               \
  p0 = -a * v0.x() + b * v0.z();                                               \
  p1 = -a * v1.x() + b * v1.z();                                               \
  p2 = -a * v2.x() + b * v2.z();                                               \
  rad = fa * box_halfsize.x() + fb * box_halfsize.z();                         \
  find_min_max(p0, p1, p2, min, max);                                          \
  if (min > rad || max < -rad)                                                 \
    return false;

#define AXISTEST_Z(a, b, fa, fb)                                               \
  p0 = a * v0.x() - b * v0.y();                                                \
  p1 = a * v1.x() - b * v1.y();                                                \
  p2 = a * v2.x() - b * v2.y();                                                \
  rad = fa * box_halfsize.x() + fb * box_halfsize.y();                         \
  find_min_max(p0, p1, p2, min, max);                                          \
  if (min > rad || max < -rad)                                                 \
    return false;

  fex = std::abs(e0.x());
  fey = std::abs(e0.y());
  fez = std::abs(e0.z());
  AXISTEST_X(e0.z(), e0.y(), fez, fey);
  AXISTEST_Y(e0.z(), e0.x(), fez, fex);
  AXISTEST_Z(e0.y(), e0.x(), fey, fex);

  fex = std::abs(e1.x());
  fey = std::abs(e1.y());
  fez = std::abs(e1.z());
  AXISTEST_X(e1.z(), e1.y(), fez, fey);
  AXISTEST_Y(e1.z(), e1.x(), fez, fex);
  AXISTEST_Z(e1.y(), e1.x(), fey, fex);

  fex = std::abs(e2.x());
  fey = std::abs(e2.y());
  fez = std::abs(e2.z());
  AXISTEST_X(e2.z(), e2.y(), fez, fey);
  AXISTEST_Y(e2.z(), e2.x(), fez, fex);
  AXISTEST_Z(e2.y(), e2.x(), fey, fex);

  find_min_max(v0.x(), v1.x(), v2.x(), min, max);
  if (min > box_halfsize.x() || max < -box_halfsize.x())
    return false;
  find_min_max(v0.y(), v1.y(), v2.y(), min, max);
  if (min > box_halfsize.y() || max < -box_halfsize.y())
    return false;
  find_min_max(v0.z(), v1.z(), v2.z(), min, max);
  if (min > box_halfsize.z() || max < -box_halfsize.z())
    return false;

  Vector3f normal = e0.cross(e1);
  float d = normal.dot(v0);
  float radius = normal.cwiseAbs().dot(box_halfsize);
  if (d > radius || d < -radius)
    return false;

  return true;
}

} // namespace Intersection