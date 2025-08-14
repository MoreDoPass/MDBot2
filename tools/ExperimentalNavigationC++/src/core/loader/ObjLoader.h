#pragma once

#include "core/math/Types.h" // Наш файл с Vector3d
#include <array>
#include <string>
#include <vector>

/**
 * @struct MeshData
 * @brief Простая структура для хранения геометрии меша.
 * @details Содержит два вектора: один для координат вершин и один для индексов,
 *          формирующих треугольники.
 */
struct MeshData {
  /// @brief Вектор 3D координат всех вершин.
  std::vector<Vector3d> vertices;
  /// @brief Вектор троек индексов. Каждая тройка представляет один треугольник,
  /// ссылаясь на индексы в векторе `vertices`.
  std::vector<std::array<int, 3>> indices;
};

/**
 * @class ObjLoader
 * @brief Утилитарный класс для загрузки геометрии из .obj файлов.
 * @details Предоставляет один статический метод для парсинга .obj файла
 *          и извлечения из него только необходимой информации: вершин и
 * индексов треугольников.
 */
class ObjLoader {
public:
  /**
   * @brief Загружает и парсит .obj файл.
   * @param filePath Путь к .obj файлу.
   * @return Структура MeshData, содержащая вершины и индексы.
   * @throws std::runtime_error если файл не может быть открыт.
   */
  static MeshData loadFile(const std::string &filePath);
};