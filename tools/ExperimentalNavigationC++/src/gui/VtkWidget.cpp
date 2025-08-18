#include "VtkWidget.h"
#include "shared/Logger.h"

// VTK includes
#include <vtkActor.h>
#include <vtkCellArray.h>
#include <vtkCubeSource.h> // <-- Для создания куба-прототипа
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkGlyph3D.h> // <-- Главный инструмент для рисования кубов
#include <vtkLineSource.h>
#include <vtkNew.h>
#include <vtkPointData.h>
#include <vtkPoints.h>
#include <vtkPolyData.h>
#include <vtkPolyDataMapper.h>
#include <vtkPolyLine.h>
#include <vtkProperty.h>
#include <vtkRenderWindow.h>
#include <vtkRenderer.h>
#include <vtkUnsignedCharArray.h>

#include <QVBoxLayout>

// --- Конструктор и деструктор без изменений ---
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

// --- Функции очистки ---
void VtkWidget::clear() {
  if (!m_renderer)
    return;
  qInfo(lcCore) << "Clearing entire VTK scene.";
  m_renderer->RemoveAllViewProps();
  m_meshActor = nullptr;
  m_visualizationActor = nullptr; // <-- ИЗМЕНЕНИЕ
  m_pathActor = nullptr;
  m_rayActor = nullptr;
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::clearVisualizationActor() { // <-- ПЕРЕИМЕНОВАНО
  if (m_renderer && m_visualizationActor) {
    m_renderer->RemoveActor(m_visualizationActor);
    m_visualizationActor = nullptr;
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

void VtkWidget::clearRay() {
  if (m_renderer && m_rayActor) {
    m_renderer->RemoveActor(m_rayActor);
    m_rayActor = nullptr;
    m_vtkWidget->renderWindow()->Render();
  }
}

// --- Реализация отображения точек (бывший addPoints) ---
void VtkWidget::displayPointCloud(
    const std::vector<Vector3d> &points, // <-- ПЕРЕИМЕНОВАНО
    const double color[3], float pointSize) {
  clearVisualizationActor();
  if (points.empty()) {
    qWarning(lcCore) << "displayPointCloud called with empty point set.";
    return;
  }
  qInfo(lcCore) << "Displaying" << points.size() << "points.";

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

  m_visualizationActor = vtkSmartPointer<vtkActor>::New(); // <-- ИЗМЕНЕНИЕ
  m_visualizationActor->SetMapper(mapper);
  m_visualizationActor->GetProperty()->SetPointSize(pointSize);
  m_visualizationActor->GetProperty()->SetColor(color[0], color[1], color[2]);

  m_renderer->AddActor(m_visualizationActor);
  m_vtkWidget->renderWindow()->Render();
}

void VtkWidget::displayPointCloud( // <-- ПЕРЕИМЕНОВАНО
    const std::vector<Vector3d> &points,
    const std::vector<std::array<unsigned char, 3>> &colors, float pointSize) {
  clearVisualizationActor();
  if (points.empty()) {
    qWarning(lcCore)
        << "displayPointCloud (multicolor) called with empty point set.";
    return;
  }
  if (points.size() != colors.size()) {
    qCritical(lcCore) << "Mismatch between point count and color count!";
    return;
  }
  qInfo(lcCore) << "Displaying" << points.size() << "multicolored points.";

  vtkNew<vtkPoints> vtk_points;
  vtkNew<vtkCellArray> vtk_vertices;
  vtkNew<vtkUnsignedCharArray> vtk_colors;
  vtk_colors->SetNumberOfComponents(3);
  vtk_colors->SetName("Colors");

  for (size_t i = 0; i < points.size(); ++i) {
    vtkIdType pointId = vtk_points->InsertNextPoint(
        points[i].x(), points[i].y(), points[i].z());
    vtk_vertices->InsertNextCell(1, &pointId);
    vtk_colors->InsertNextTypedTuple(colors[i].data());
  }

  vtkNew<vtkPolyData> polyData;
  polyData->SetPoints(vtk_points);
  polyData->SetVerts(vtk_vertices);
  polyData->GetPointData()->SetScalars(vtk_colors);

  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputData(polyData);
  mapper->ScalarVisibilityOn();
  mapper->SetScalarModeToUsePointData();
  mapper->SetColorModeToDirectScalars();

  m_visualizationActor = vtkSmartPointer<vtkActor>::New(); // <-- ИЗМЕНЕНИЕ
  m_visualizationActor->SetMapper(mapper);
  m_visualizationActor->GetProperty()->SetPointSize(pointSize);

  m_renderer->AddActor(m_visualizationActor);
  m_vtkWidget->renderWindow()->Render();
}

// --- НОВАЯ РЕАЛИЗАЦИЯ ДЛЯ ОТОБРАЖЕНИЯ КУБОВ ---
void VtkWidget::displayVoxelCubes(
    const std::vector<Vector3d> &centers,
    const std::vector<std::array<unsigned char, 3>> &colors,
    const Vector3d &voxelSize) {

  clearVisualizationActor();
  if (centers.empty()) {
    qWarning(lcCore) << "displayVoxelCubes called with empty center set.";
    return;
  }
  if (centers.size() != colors.size()) {
    qCritical(lcCore) << "Mismatch between voxel center count ("
                      << centers.size() << ") and color count ("
                      << colors.size() << ")!";
    return;
  }

  qInfo(lcCore) << "Displaying" << centers.size() << "voxels as cubes.";

  // --- Шаг 1: Создаем точки и цвета (как для облака точек) ---
  vtkNew<vtkPoints> vtk_points;
  vtkNew<vtkUnsignedCharArray> vtk_colors;
  vtk_colors->SetNumberOfComponents(3);
  vtk_colors->SetName("Colors");

  for (size_t i = 0; i < centers.size(); ++i) {
    vtk_points->InsertNextPoint(centers[i].x(), centers[i].y(), centers[i].z());
    vtk_colors->InsertNextTypedTuple(colors[i].data());
  }

  // Создаем PolyData и привязываем к ней точки и цвета
  vtkNew<vtkPolyData> polyData;
  polyData->SetPoints(vtk_points);
  polyData->GetPointData()->SetScalars(vtk_colors);

  // --- Шаг 2: Создаем прототип геометрии - один куб ---
  vtkNew<vtkCubeSource> cubeSource;
  cubeSource->SetXLength(voxelSize.x());
  cubeSource->SetYLength(voxelSize.y());
  cubeSource->SetZLength(voxelSize.z());

  // --- Шаг 3: Создаем Glyph3D, который будет копировать куб в каждую точку ---
  vtkNew<vtkGlyph3D> glyph;
  glyph->SetInputData(polyData);
  glyph->SetSourceConnection(cubeSource->GetOutputPort());
  glyph->SetScaleModeToDataScalingOff();
  glyph->SetColorModeToColorByScalar();
  glyph->Update();

  // --- Шаг 4: Создаем маппер и актора для отображения ---
  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputConnection(glyph->GetOutputPort());

  m_visualizationActor = vtkSmartPointer<vtkActor>::New();
  m_visualizationActor->SetMapper(mapper);

  // === ИЗМЕНЕНИЕ ЗДЕСЬ! ===
  // Добавляем черный контур для каждого куба, чтобы они не сливались.
  m_visualizationActor->GetProperty()->SetEdgeVisibility(
      true); // Включаем видимость граней
  m_visualizationActor->GetProperty()->SetEdgeColor(
      0, 0, 0); // Устанавливаем цвет граней (черный)
  m_visualizationActor->GetProperty()->SetLineWidth(
      1.0); // Устанавливаем толщину линии

  m_renderer->AddActor(m_visualizationActor);
  m_vtkWidget->renderWindow()->Render();
}

// --- Остальные методы add... без изменений ---
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
  clearRay();
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