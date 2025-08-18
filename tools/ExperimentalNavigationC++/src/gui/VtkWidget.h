#pragma once

#include "core/math/Types.h"
#include <QFrame>
#include <QVTKOpenGLNativeWidget.h>
#include <array>
#include <vector>
#include <vtkActor.h>
#include <vtkPolyData.h>
#include <vtkRenderWindow.h>
#include <vtkRenderer.h>
#include <vtkSmartPointer.h>

class QVBoxLayout;

/**
 * @class VtkWidget
 * @brief Виджет для отображения 3D-сцены с использованием VTK.
 * @details Инкапсулирует логику создания и управления объектами VTK (акторами),
 *          такими как меши, точки, пути и воксели.
 */
class VtkWidget : public QFrame {
  Q_OBJECT

public:
  explicit VtkWidget(QWidget *parent = nullptr);
  ~VtkWidget() override;

  /** @brief Полностью очищает сцену от всех объектов. */
  void clear();

  /** @brief Удаляет только актора, отвечающего за визуализацию (точки/воксели).
   */
  void clearVisualizationActor(); // <-- ПЕРЕИМЕНОВАНО

  /** @brief Удаляет только линию пути со сцены. */
  void clearPath();

  /** @brief Удаляет только линию луча со сцены. */
  void clearRay();

  // --- МЕТОДЫ ВИЗУАЛИЗАЦИИ ---

  /**
   * @brief Отображает набор точек в виде простого одноцветного облака.
   * @param points Вектор с 3D-координатами центров.
   * @param color Цвет точек (массив из 3-х double).
   * @param pointSize Размер точек.
   */
  void displayPointCloud(const std::vector<Vector3d> &points,
                         const double color[3],
                         float pointSize = 3.0f); // <-- ПЕРЕИМЕНОВАНО

  /**
   * @brief Отображает набор точек в виде разноцветного облака.
   * @param points Вектор с 3D-координатами центров.
   * @param colors Вектор с цветами для каждой точки (R, G, B, 0-255).
   * @param pointSize Размер точек.
   */
  void
  displayPointCloud(const std::vector<Vector3d> &points,
                    const std::vector<std::array<unsigned char, 3>> &colors,
                    float pointSize = 3.0f); // <-- ПЕРЕИМЕНОВАНО

  /**
   * @brief (НОВЫЙ МЕТОД) Отображает воксели в виде кубов.
   * @details Использует vtkGlyph3D для эффективного рендеринга множества кубов.
   * @param centers Вектор с 3D-координатами центров вокселей.
   * @param colors Вектор с цветами для каждого куба (R, G, B, 0-255).
   * @param voxelSize Размеры одного вокселя (ширина, глубина, высота).
   */
  void
  displayVoxelCubes(const std::vector<Vector3d> &centers,
                    const std::vector<std::array<unsigned char, 3>> &colors,
                    const Vector3d &voxelSize); // <-- НОВАЯ ФУНКЦИЯ

  // --- Остальные методы ---

  void addMesh(vtkPolyData *polyData, const double color[3] = nullptr,
               double opacity = 1.0);
  void addPath(const std::vector<Vector3d> &pathPoints);
  void addRay(const Vector3d &start, const Vector3d &end, const double color[3],
              float lineWidth = 4.0f);
  void resetCamera();

  vtkRenderer *getRenderer() { return m_renderer; }
  vtkRenderWindow *GetRenderWindow() { return m_vtkWidget->renderWindow(); }

private:
  QVTKOpenGLNativeWidget *m_vtkWidget = nullptr;
  vtkRenderer *m_renderer = nullptr;

  /// @brief Указатель на актора, отображающего исходный меш.
  vtkSmartPointer<vtkActor> m_meshActor;
  /// @brief Указатель на актора, отображающего путь.
  vtkSmartPointer<vtkActor> m_pathActor;
  /// @brief Указатель на актора, отображающего тестовый луч.
  vtkSmartPointer<vtkActor> m_rayActor;

  /// @brief Умный указатель на актора для основной визуализации (точки или
  /// воксели).
  vtkSmartPointer<vtkActor> m_visualizationActor; // <-- ПЕРЕИМЕНОВАНО
};