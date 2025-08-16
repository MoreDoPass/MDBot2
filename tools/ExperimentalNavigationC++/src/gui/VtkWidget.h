#pragma once

#include "core/math/Types.h"
#include <QFrame>
#include <QVTKOpenGLNativeWidget.h>
#include <array> // <-- Добавили для std::array
#include <vector>
#include <vtkActor.h>
#include <vtkPolyData.h>
#include <vtkRenderWindow.h> // <--- И этот тоже
#include <vtkRenderer.h>
#include <vtkSmartPointer.h>

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
   * @brief Добавляет на сцену линию, представляющую луч.
   * @param start Начальная точка луча.
   * @param end Конечная точка луча.
   * @param color Цвет линии (массив из 3-х double-компонент).
   * @param lineWidth Толщина линии.
   */
  void addRay(const Vector3d &start, const Vector3d &end, const double color[3],
              float lineWidth = 4.0f);

  /**
   * @brief Удаляет только линию луча со сцены.
   */
  void clearRay();

  /**
   * @brief Удаляет только облако точек со сцены.
   */
  void clearPoints();

  /**
   * @brief Удаляет только линию пути со сцены.
   */
  void clearPath();

  // Старая версия для простого одноцветного облака
  void addPoints(const std::vector<Vector3d> &points,
                 const double color[3] = nullptr, float pointSize = 3.0f);

  // --- НОВАЯ ВЕРСИЯ ДЛЯ РАЗНОЦВЕТНОГО ОБЛАКА ---
  /**
   * @brief Добавляет на сцену облако точек с индивидуальным цветом для каждой
   * точки.
   * @param points Вектор с 3D-координатами точек.
   * @param colors Вектор с цветами. Каждый цвет - это массив из 3-х
   *               компонент (R, G, B) в диапазоне 0-255.
   * @param pointSize Размер точек.
   * @note Вектор `colors` должен быть того же размера, что и вектор `points`.
   */
  void addPoints(const std::vector<Vector3d> &points,
                 const std::vector<std::array<unsigned char, 3>> &colors,
                 float pointSize = 3.0f);

  void addMesh(vtkPolyData *polyData, const double color[3] = nullptr,
               double opacity = 1.0);

  void addPath(const std::vector<Vector3d> &pathPoints);

  void resetCamera();

  // --- НОВЫЕ ПУБЛИЧНЫЕ МЕТОДЫ ДОСТУПА ---
  /**
   * @brief Возвращает указатель на рендерер VTK.
   * @return Указатель на vtkRenderer.
   */
  vtkRenderer *getRenderer() { return m_renderer; }

  /**
   * @brief Возвращает указатель на окно рендеринга VTK.
   * @return Указатель на vtkRenderWindow.
   */
  vtkRenderWindow *GetRenderWindow() { return m_vtkWidget->renderWindow(); }

private:
  QVTKOpenGLNativeWidget *m_vtkWidget = nullptr;
  vtkRenderer *m_renderer = nullptr;

  /// @brief Умный указатель на актора, отображающего исходный меш.
  vtkSmartPointer<vtkActor> m_meshActor;
  /// @brief Умный указатель на актора, отображающего облако точек (воксели).
  vtkSmartPointer<vtkActor> m_pointsActor;
  /// @brief Умный указатель на актора, отображающего найденный путь.
  vtkSmartPointer<vtkActor> m_pathActor;
  /// @brief Умный указатель на актора, отображающего тестовый луч.
  vtkSmartPointer<vtkActor> m_rayActor;
};