#pragma once

#include "core/loader/ObjLoader.h" // Нужна структура MeshData
#include "core/math/Types.h"       // Нужен Vector3d

/**
 * @class MeshFilter
 * @brief Утилитарный класс для предварительной обработки полигональных сеток.
 * @details Предоставляет статические методы для фильтрации геометрии перед
 *          тем, как она будет передана в вокселизатор.
 */
class MeshFilter {
public:
  /**
   * @brief Фильтрует меш, оставляя только те треугольники, угол наклона
   *        которых меньше заданного.
   * @param inputMesh Исходная геометрия.
   * @param maxSlope Максимально допустимый угол наклона в градусах. Полигоны с
   *                 наклоном больше этого значения будут отброшены.
   * @return Новая структура MeshData, содержащая только "проходимые"
   *         треугольники.
   */
  static MeshData filterBySlope(const MeshData &inputMesh, double maxSlope);
};