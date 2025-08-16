#include "VtkWidget.h"
#include "shared/Logger.h"

#include <vtkActor.h>
#include <vtkCellArray.h>
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkLineSource.h>
#include <vtkNew.h>
#include <vtkPointData.h> // <-- Нужно для привязки цветов
#include <vtkPoints.h>
#include <vtkPolyData.h>
#include <vtkPolyDataMapper.h>
#include <vtkPolyLine.h>
#include <vtkProperty.h>
#include <vtkRenderWindow.h>
#include <vtkRenderer.h>
#include <vtkUnsignedCharArray.h> // <-- Специальный массив VTK для цветов


#include <QVBoxLayout>

// ... конструктор и деструктор без изменений ...
VtkWidget::VtkWidget(QWidget *parent) : QFrame(parent) {
  vtkNew<vtkGenericOpenGLRenderWindow> renderWindow;
  m_vtkWidget = new QVTKOpenGLNativeWidget(this);
  m_vtkWidget->setRenderWindow(renderWindow);

  vtkNew<vtkRenderer> renderer;
  renderer->SetBackground(0.2, 0.3, 0.4);
  m_vtkWidget->renderWindow()->AddRenderer(renderer);
  m_renderer = renderer.Get();

  m_vtkWidget->interactor()->Initialize();

  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->addWidget(m_vtkWidget);

  qInfo(lcApp) << "VtkWidget created.";
}

VtkWidget::~VtkWidget() { qInfo(lcApp) << "VtkWidget destroyed."; }

// ... clear, clearPoints, clearPath без изменений ...
void VtkWidget::clear() {
  if (!m_renderer)
    return;
  qInfo(lcCore) << "Clearing entire VTK scene.";
  m_renderer->RemoveAllViewProps();
  m_meshActor = nullptr;
  m_pointsActor = nullptr;
  m_pathActor = nullptr;
  m_rayActor = nullptr; // <--- ДОБАВЛЕНО
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::clearRay() {
  if (m_renderer && m_rayActor) {
    m_renderer->RemoveActor(m_rayActor);
    m_rayActor = nullptr;
    m_vtkWidget->renderWindow()->Render();
  }
}

void VtkWidget::clearPoints() {
  if (m_renderer && m_pointsActor) {
    m_renderer->RemoveActor(m_pointsActor);
    m_pointsActor = nullptr;
    m_vtkWidget->renderWindow()->Render();
  }
}

void VtkWidget::clearPath() {
  if (m_renderer && m_pathActor) {
    m_renderer->RemoveActor(m_pathActor);
    m_pathActor = nullptr;
    m_vtkWidget->renderWindow()->Render();
  }
}

// ... старая версия addPoints без изменений ...
void VtkWidget::addPoints(const std::vector<Vector3d> &points,
                          const double color[3], float pointSize) {
  clearPoints();
  if (points.empty()) {
    qWarning(lcCore)
        << "addPoints called with empty point set. Points cleared.";
    return;
  }
  qInfo(lcCore) << "Adding" << points.size() << "points to the scene.";

  vtkNew<vtkPoints> vtk_points;
  vtkNew<vtkCellArray> vtk_vertices;
  for (const auto &point : points) {
    vtkIdType pointId =
        vtk_points->InsertNextPoint(point.x(), point.y(), point.z());
    vtk_vertices->InsertNextCell(1, &pointId);
  }
  vtkNew<vtkPolyData> polyData;
  polyData->SetPoints(vtk_points);
  polyData->SetVerts(vtk_vertices);

  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(polyData);

  m_pointsActor = vtkSmartPointer<vtkActor>::New();
  m_pointsActor->SetMapper(mapper);
  m_pointsActor->GetProperty()->SetPointSize(pointSize);
  if (color) {
    m_pointsActor->GetProperty()->SetColor(color[0], color[1], color[2]);
  } else {
    m_pointsActor->GetProperty()->SetColor(0.0, 1.0, 0.0);
  }
  m_renderer->AddActor(m_pointsActor);
  m_vtkWidget->renderWindow()->Render();
}

// --- РЕАЛИЗАЦИЯ НОВОЙ ВЕРСИИ ADDPOINTS ---
void VtkWidget::addPoints(
    const std::vector<Vector3d> &points,
    const std::vector<std::array<unsigned char, 3>> &colors, float pointSize) {
  clearPoints();

  if (points.empty()) {
    qWarning(lcCore) << "addPoints (multicolor) called with empty point set.";
    return;
  }
  if (points.size() != colors.size()) {
    qCritical(lcCore) << "Mismatch between point count (" << points.size()
                      << ") and color count (" << colors.size() << ")!";
    return;
  }

  qInfo(lcCore) << "Adding" << points.size()
                << "multicolored points to the scene.";

  vtkNew<vtkPoints> vtk_points;
  vtkNew<vtkCellArray> vtk_vertices;
  // Создаем специальный массив для цветов
  vtkNew<vtkUnsignedCharArray> vtk_colors;
  vtk_colors->SetNumberOfComponents(3); // 3 компонента на цвет (R, G, B)
  vtk_colors->SetName("Colors");

  for (size_t i = 0; i < points.size(); ++i) {
    // Добавляем геометрию точки
    vtkIdType pointId = vtk_points->InsertNextPoint(
        points[i].x(), points[i].y(), points[i].z());
    vtk_vertices->InsertNextCell(1, &pointId);
    // Добавляем цвет для этой точки
    vtk_colors->InsertNextTypedTuple(colors[i].data());
  }

  vtkNew<vtkPolyData> polyData;
  polyData->SetPoints(vtk_points);
  polyData->SetVerts(vtk_vertices);

  // "Приклеиваем" массив цветов к точкам
  polyData->GetPointData()->SetScalars(vtk_colors);

  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(polyData);
  // Говорим мапперу использовать наши цвета
  mapper->ScalarVisibilityOn();
  mapper->SetScalarModeToUsePointData();
  mapper->SetColorModeToDirectScalars();

  m_pointsActor = vtkSmartPointer<vtkActor>::New();
  m_pointsActor->SetMapper(mapper);
  m_pointsActor->GetProperty()->SetPointSize(pointSize);

  m_renderer->AddActor(m_pointsActor);
  m_vtkWidget->renderWindow()->Render();
}

// ... addMesh, addPath, resetCamera без изменений ...
void VtkWidget::addMesh(vtkPolyData *polyData, const double color[3],
                        double opacity) {
  if (m_meshActor) {
    m_renderer->RemoveActor(m_meshActor);
  }

  if (!polyData) {
    qWarning(lcCore) << "addMesh called with null polyData.";
    return;
  }
  qInfo(lcCore) << "Adding mesh to the scene...";

  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(polyData);

  m_meshActor = vtkSmartPointer<vtkActor>::New();
  m_meshActor->SetMapper(mapper);

  m_meshActor->GetProperty()->SetOpacity(opacity);
  if (color) {
    m_meshActor->GetProperty()->SetColor(color[0], color[1], color[2]);
  } else {
    m_meshActor->GetProperty()->SetColor(0.8, 0.8, 0.8);
  }

  m_renderer->AddActor(m_meshActor);
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::addPath(const std::vector<Vector3d> &pathPoints) {
  clearPath();
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

  m_pathActor = vtkSmartPointer<vtkActor>::New();
  m_pathActor->SetMapper(mapper);
  m_pathActor->GetProperty()->SetColor(1.0, 0.0, 0.0); // Красный
  m_pathActor->GetProperty()->SetLineWidth(4.0);

  m_renderer->AddActor(m_pathActor);
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::addRay(const Vector3d &start, const Vector3d &end,
                       const double color[3], float lineWidth) {
  clearRay(); // Сначала удаляем старый луч

  vtkNew<vtkLineSource> lineSource;
  lineSource->SetPoint1(start.data());
  lineSource->SetPoint2(end.data());

  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(lineSource->GetOutput());

  m_rayActor = vtkSmartPointer<vtkActor>::New();
  m_rayActor->SetMapper(mapper);

  m_rayActor->GetProperty()->SetColor(color[0], color[1], color[2]);
  m_rayActor->GetProperty()->SetLineWidth(lineWidth);

  m_renderer->AddActor(m_rayActor);
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