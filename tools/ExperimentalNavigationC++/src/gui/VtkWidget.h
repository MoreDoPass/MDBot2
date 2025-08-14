#pragma once

#include "core/math/Types.h" // <--- ДОБАВИТЬ
#include "core/pathfinder/NavGraph.h"
#include <QFrame>
#include <QVTKOpenGLNativeWidget.h> // <--- ВКЛЮЧАЕМ ПРЯМО ЗДЕСЬ
#include <vector>                   // <--- ДОБАВИТЬ
#include <vtkCamera.h>
#include <vtkPolyData.h>
#include <vtkRenderer.h> // <--- И ЭТО ТОЖЕ

class QVBoxLayout; // Это можно оставить

class VtkWidget : public QFrame {
  Q_OBJECT

public:
  explicit VtkWidget(QWidget *parent = nullptr);
  ~VtkWidget() override;

  void clear();

  /**
   * @brief Добавляет облако точек на сцену.
   * @param points Вектор 3D-координат для отображения.
   * @param color Цвет точек.
   * @param pointSize Размер точек.
   */
  void addPoints(const std::vector<Vector3d> &points,
                 const double color[3] = nullptr, float pointSize = 3.0f);

  /**
   * @brief Добавляет 3D-меш на сцену.
   * @param polyData Указатель на данные меша в формате VTK.
   * @param color Цвет меша.
   * @param opacity Прозрачность (от 0.0 до 1.0).
   */
  void addMesh(vtkPolyData *polyData, const double color[3] = nullptr,
               double opacity = 1.0);

  /// @brief Рисует путь в виде красной линии.
  void addPath(const std::vector<Vector3d> &pathPoints);

  /// @brief Рисует ребра навигационного графа
  void addGraphEdges(const std::vector<Vector3d> &nodes,
                     const AdjacencyList &adj);

  /// @brief Сбрасывает камеру, чтобы все объекты были видны.
  void resetCamera();

private:
  QVTKOpenGLNativeWidget *m_vtkWidget = nullptr;
  vtkRenderer *m_renderer = nullptr;
};