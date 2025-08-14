#pragma once

#include "../math/Types.h"
#include <string>
#include <vector>

// --- Прямое включение заголовочных файлов VTK ---
#include <vtkSmartPointer.h>

// --- Прямое объявление классов, которые мы используем как указатели ---
class vtkPolyData;
class vtkCellLocator; // Используем vtkCellLocator вместо vtkOBBTree

/**
 * @class Voxelizer
 * @brief На самом деле NavMeshGenerator. Отвечает за создание проходимого меша
 * из сырой геометрии.
 * @details Загружает меш, фильтрует полигоны по углу наклона и высоте
 * (клиренсу) агента.
 */
class Voxelizer {
public:
  /**
   * @brief Конструктор.
   * @param meshPath Путь к .obj файлу.
   */
  explicit Voxelizer(const std::string &meshPath);

  /**
   * @brief Запускает полный процесс генерации проходимого меша.
   * @return true в случае успеха, иначе false.
   */
  bool build();

  /**
   * @brief Возвращает меш, состоящий только из проходимых полигонов.
   * @return Умный указатель на vtkPolyData.
   */
  vtkSmartPointer<vtkPolyData> getWalkableMesh() const;

  /**
   * @brief Возвращает указатель на исходный загруженный меш.
   * @return Умный указатель на vtkPolyData.
   */
  vtkSmartPointer<vtkPolyData> getRawMesh() const;

private:
  /// @brief Путь к исходному файлу .obj.
  std::string m_meshPath;

  /// @brief Умный указатель на исходную, полную геометрию.
  vtkSmartPointer<vtkPolyData> m_rawMesh;

  /// @brief Умный указатель на структуру для ускорения рейкастинга.
  vtkSmartPointer<vtkCellLocator> m_locator;

  /// @brief Умный указатель на результат - меш, состоящий только из проходимых
  /// полигонов.
  vtkSmartPointer<vtkPolyData> m_walkableMesh;
};