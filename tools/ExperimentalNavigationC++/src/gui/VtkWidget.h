#pragma once

#include "core/math/Types.h"
#include "core/pathfinder/NavGraph.h"
#include <QFrame>
#include <QVTKOpenGLNativeWidget.h>
#include <vector>
#include <vtkActor.h> // <-- Добавляем
#include <vtkPolyData.h>
#include <vtkRenderer.h>
#include <vtkSmartPointer.h> // <-- Добавляем

class QVBoxLayout;

class VtkWidget : public QFrame {
  Q_OBJECT

public:
  explicit VtkWidget(QWidget *parent = nullptr);
  ~VtkWidget() override;

  /**
   * @brief Полностью очищает сцену от всех объектов.
   */
  void clear();

  /**
   * @brief Удаляет только облако точек со сцены.
   */
  void clearPoints();

  /**
   * @brief Удаляет только линию пути со сцены.
   */
  void clearPath();

  void addPoints(const std::vector<Vector3d> &points,
                 const double color[3] = nullptr, float pointSize = 3.0f);

  void addMesh(vtkPolyData *polyData, const double color[3] = nullptr,
               double opacity = 1.0);

  void addPath(const std::vector<Vector3d> &pathPoints);

  void addGraphEdges(const std::vector<Vector3d> &nodes,
                     const AdjacencyList &adj);

  void resetCamera();

private:
  QVTKOpenGLNativeWidget *m_vtkWidget = nullptr;
  vtkRenderer *m_renderer = nullptr;

  /// @brief Умный указатель на актора, отображающего исходный меш.
  vtkSmartPointer<vtkActor> m_meshActor;
  /// @brief Умный указатель на актора, отображающего облако точек (воксели).
  vtkSmartPointer<vtkActor> m_pointsActor;
  /// @brief Умный указатель на актора, отображающего найденный путь.
  vtkSmartPointer<vtkActor> m_pathActor;
  /// @brief Умный указатель на актора, отображающего граф (для будущих нужд).
  vtkSmartPointer<vtkActor> m_graphActor;
};