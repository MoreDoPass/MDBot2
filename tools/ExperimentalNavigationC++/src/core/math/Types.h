#pragma once

#include <Eigen/Dense> // Подключаем главную часть библиотеки Eigen
#include <functional>  // Нужно для std::hash

/**
 * @file Types.h
 * @brief Определения основных математических и навигационных типов данных.
 * @details Этот файл содержит алиасы для векторов и матриц из Eigen,
 *          а также структуры для воксельных координат и их хэширования.
 */

// --- Типы данных из Eigen ---
// Создаем удобные и короткие псевдонимы для типов Eigen.
// Вместо того, чтобы каждый раз писать Eigen::Vector3d, мы сможем писать
// Vector3d. 'd' в конце означает, что мы используем тип double для координат.
using Vector3d = Eigen::Vector3d;
using TransformMatrix = Eigen::Matrix4d;

// --- Структура для воксельных координат ---
/**
 * @struct VoxelCoord
 * @brief Представляет координату одного вокселя в целочисленной сетке.
 */
struct VoxelCoord {
  int x = 0;
  int y = 0;
  int z = 0;

  /**
   * @brief Оператор сравнения. Нужен для того, чтобы можно было искать
   *        элементы в std::unordered_set и сравнивать их.
   */
  bool operator==(const VoxelCoord &other) const {
    return x == other.x && y == other.y && z == other.z;
  }
};

// --- Хэш-функция для VoxelCoord ---
// Это самый сложный, но необходимый блок.
// Чтобы класть наш собственный тип (VoxelCoord) в std::unordered_set,
// мы должны научить C++ как его "хэшировать" (превращать в одно число).
// Мы делаем это, специализируя шаблон std::hash для нашего типа.

namespace std {
template <> struct hash<VoxelCoord> {
  /**
   * @brief Оператор вызова, который вычисляет хэш для VoxelCoord.
   * @param v Координата вокселя, которую нужно хэшировать.
   * @return size_t Хэш-значение.
   */
  size_t operator()(const VoxelCoord &v) const {
    // Это простая, но эффективная хэш-функция.
    // Мы берем хэши от каждой координаты по отдельности
    // и комбинируем их с помощью побитовых операций,
    // чтобы уменьшить количество коллизий (когда у разных
    // координат получается одинаковый хэш).
    size_t h1 = hash<int>()(v.x);
    size_t h2 = hash<int>()(v.y);
    size_t h3 = hash<int>()(v.z);

    // Комбинируем хэши
    size_t seed = h1;
    seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    return seed;
  }
};
} // namespace std