#include "VtkWidget.h"
#include "shared/Logger.h"

// Основные заголовочные файлы VTK, которые нам нужны
#include <vtkActor.h> // Представляет объект на сцене
#include <vtkCellArray.h> // Контейнер для описания "клеток" (вершин, линий, полигонов)
#include <vtkCellArray.h>
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkGenericRenderWindowInteractor.h>
#include <vtkLine.h>
#include <vtkNew.h> // <--- Нужен для vtkNew
#include <vtkNew.h>
#include <vtkPoints.h> // Контейнер для хранения 3D-точек
#include <vtkPolyData.h> // Объект для представления геометрии (в нашем случае - точек)
#include <vtkPolyDataMapper.h> // Преобразует геометрию в графические примитивы
#include <vtkPolyLine.h>
#include <vtkProperty.h> // Свойства актора (цвет, размер и т.д.)
#include <vtkRenderWindow.h>
#include <vtkRendererCollection.h>

// Заголовки Qt
#include <QVBoxLayout>

VtkWidget::VtkWidget(QWidget *parent) : QFrame(parent) {
  // 1. Создаем окно рендеринга
  vtkNew<vtkGenericOpenGLRenderWindow> renderWindow;

  // 2. Создаем наш главный виджет Qt
  m_vtkWidget = new QVTKOpenGLNativeWidget(this);
  m_vtkWidget->setRenderWindow(renderWindow);

  // --- ИСПРАВЛЕНИЕ ---
  // Мы не полагаемся на рендерер по умолчанию.
  // Мы создаем его сами и добавляем в окно.

  // 3. Создаем новый экземпляр рендерера (сцены)
  vtkNew<vtkRenderer> renderer;
  renderer->SetBackground(0.2, 0.3, 0.4); // Задаем фон здесь

  // 4. Добавляем наш рендерер в окно рендеринга
  m_vtkWidget->renderWindow()->AddRenderer(renderer);

  // 5. Сохраняем указатель на наш рендерер
  m_renderer =
      renderer.Get(); // .Get() извлекает обычный указатель из умного vtkNew

  // -------------------

  // 6. Инициализируем интерактор (управление камерой)
  m_vtkWidget->interactor()->Initialize();

  // Настраиваем лэйаут
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->addWidget(m_vtkWidget);

  qInfo(lcApp) << "VtkWidget created.";
}

VtkWidget::~VtkWidget() { qInfo(lcApp) << "VtkWidget destroyed."; }

void VtkWidget::clear() {
  if (!m_renderer)
    return;
  qInfo(lcCore) << "Clearing VTK scene.";
  m_renderer->RemoveAllViewProps();
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::addPoints(const std::vector<Vector3d> &points,
                          const double color[3], float pointSize) {
  if (points.empty()) {
    qWarning(lcCore) << "addPoints called with empty point set.";
    return;
  }

  qInfo(lcCore) << "Adding" << points.size() << "points to the scene.";

  // --- Шаг 1: Создаем геометрию ---

  // Создаем умный указатель на объект для хранения координат
  vtkNew<vtkPoints> vtk_points;
  // Создаем умный указатель на объект для хранения "вершин"
  // Каждая точка в нашем облаке - это одна вершина.
  vtkNew<vtkCellArray> vtk_vertices;

  // Проходимся по всем точкам из нашего вектора
  for (const auto &point : points) {
    // Добавляем координаты в vtkPoints и получаем ID этой точки
    vtkIdType pointId =
        vtk_points->InsertNextPoint(point.x(), point.y(), point.z());
    // Говорим vtk_vertices: "создай новую вершину, используя одну точку с ID =
    // pointId"
    vtk_vertices->InsertNextCell(1, &pointId);
  }

  // Создаем главный объект vtkPolyData - "полигональные данные"
  vtkNew<vtkPolyData> polyData;
  // Устанавливаем в него наши наборы координат и вершин
  polyData->SetPoints(vtk_points);
  polyData->SetVerts(vtk_vertices);

  // --- Шаг 2: Создаем Mapper ---
  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(polyData); // Говорим мапперу, какие данные использовать

  // --- Шаг 3: Создаем Actor ---
  vtkNew<vtkActor> actor;
  actor->SetMapper(mapper); // Подключаем к актору наш маппер

  // Настраиваем свойства отображения (цвет, размер)
  actor->GetProperty()->SetPointSize(pointSize);
  if (color) {
    actor->GetProperty()->SetColor(color[0], color[1], color[2]);
  } else {
    // Цвет по умолчанию - ярко-зеленый
    actor->GetProperty()->SetColor(0.0, 1.0, 0.0);
  }

  // Наконец, добавляем наш Actor на сцену (рендерер)
  m_renderer->AddActor(actor);
  // Сбрасываем камеру, чтобы все точки были видны
  m_renderer->ResetCamera();
  // Перерисовываем окно, чтобы увидеть изменения
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::addMesh(vtkPolyData *polyData, const double color[3],
                        double opacity) {
  if (!polyData) {
    qWarning(lcCore) << "addMesh called with null polyData.";
    return;
  }

  qInfo(lcCore) << "Adding mesh to the scene...";

  // Создаем Mapper и Actor, как и для точек
  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(polyData);

  vtkNew<vtkActor> actor;
  actor->SetMapper(mapper);

  // Настраиваем свойства
  actor->GetProperty()->SetOpacity(opacity);
  if (color) {
    actor->GetProperty()->SetColor(color[0], color[1], color[2]);
  } else {
    // Цвет по умолчанию - светло-серый
    actor->GetProperty()->SetColor(0.8, 0.8, 0.8);
  }

  m_renderer->AddActor(actor);
  // Камеру здесь не сбрасываем, сделаем это после добавления точек.
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::addPath(const std::vector<Vector3d> &pathPoints) {
  if (pathPoints.size() < 2)
    return;

  vtkNew<vtkPoints> points;
  for (const auto &p : pathPoints) {
    points->InsertNextPoint(p.x(), p.y(), p.z());
  }

  vtkNew<vtkPolyLine> polyLine;
  polyLine->GetPointIds()->SetNumberOfIds(pathPoints.size());
  for (unsigned int i = 0; i < pathPoints.size(); i++) {
    polyLine->GetPointIds()->SetId(i, i);
  }

  vtkNew<vtkCellArray> cells;
  cells->InsertNextCell(polyLine);

  vtkNew<vtkPolyData> polyData;
  polyData->SetPoints(points);
  polyData->SetLines(cells);

  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(polyData);

  vtkNew<vtkActor> actor;
  actor->SetMapper(mapper);
  actor->GetProperty()->SetColor(1.0, 0.0, 0.0); // Красный
  actor->GetProperty()->SetLineWidth(4.0);

  // Добавляем актор с именем "path", чтобы можно было его удалить
  m_renderer->AddActor(actor);
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::resetCamera() {
  if (m_renderer) {
    qInfo(lcCore) << "Resetting camera.";
    m_renderer->ResetCamera();
    m_vtkWidget->renderWindow()->Render();
  } else {
    qWarning(lcCore) << "Cannot reset camera, renderer is null.";
  }
}

void VtkWidget::addGraphEdges(const std::vector<Vector3d> &nodes,
                              const AdjacencyList &adj) {
  if (nodes.empty())
    return;

  vtkNew<vtkPoints> points;
  vtkNew<vtkCellArray> lines;

  // Сначала добавляем все узлы как точки в vtkPoints
  for (const auto &node : nodes) {
    points->InsertNextPoint(node.x(), node.y(), node.z());
  }

  // Теперь создаем линии (ребра)
  for (size_t i = 0; i < adj.size(); ++i) {
    for (int neighborId : adj[i]) {
      // Чтобы не рисовать каждое ребро дважды, рисуем только если i <
      // neighborId
      if (i < neighborId) {
        vtkNew<vtkLine> line;
        line->GetPointIds()->SetId(0, i);
        line->GetPointIds()->SetId(1, neighborId);
        lines->InsertNextCell(line);
      }
    }
  }

  vtkNew<vtkPolyData> polyData;
  polyData->SetPoints(points);
  polyData->SetLines(lines);

  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(polyData);

  vtkNew<vtkActor> actor;
  actor->SetMapper(mapper);
  actor->GetProperty()->SetColor(0.2, 0.2, 1.0); // Синий
  actor->GetProperty()->SetLineWidth(1.0);
  actor->GetProperty()->SetOpacity(0.5); // Полупрозрачный

  m_renderer->AddActor(actor);
  m_vtkWidget->renderWindow()->Render();
}