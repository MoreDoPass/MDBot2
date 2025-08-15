#include "VtkWidget.h"
#include "shared/Logger.h"

#include <vtkActor.h>
#include <vtkCellArray.h>
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkLine.h>
#include <vtkNew.h>
#include <vtkPoints.h>
#include <vtkPolyData.h>
#include <vtkPolyDataMapper.h>
#include <vtkPolyLine.h>
#include <vtkProperty.h>
#include <vtkRenderWindow.h>
#include <vtkRendererCollection.h>

#include <QVBoxLayout>

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

void VtkWidget::clear() {
  if (!m_renderer)
    return;
  qInfo(lcCore) << "Clearing entire VTK scene.";
  m_renderer->RemoveAllViewProps();
  m_meshActor = nullptr;
  m_pointsActor = nullptr;
  m_pathActor = nullptr;
  m_graphActor = nullptr;
  m_vtkWidget->renderWindow()->Render();
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

void VtkWidget::addPoints(const std::vector<Vector3d> &points,
                          const double color[3], float pointSize) {
  // Сначала удаляем старое облако точек, если оно было
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

  // Создаем нового актора и сохраняем его
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
  // Удаляем старый путь
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
  if (m_graphActor) {
    m_renderer->RemoveActor(m_graphActor);
  }
  if (nodes.empty())
    return;

  vtkNew<vtkPoints> points;
  vtkNew<vtkCellArray> lines;

  for (const auto &node : nodes) {
    points->InsertNextPoint(node.x(), node.y(), node.z());
  }

  for (size_t i = 0; i < adj.size(); ++i) {
    for (int neighborId : adj[i]) {
      if (i < (size_t)neighborId) {
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

  m_graphActor = vtkSmartPointer<vtkActor>::New();
  m_graphActor->SetMapper(mapper);
  m_graphActor->GetProperty()->SetColor(0.2, 0.2, 1.0);
  m_graphActor->GetProperty()->SetLineWidth(1.0);
  m_graphActor->GetProperty()->SetOpacity(0.5);

  m_renderer->AddActor(m_graphActor);
  m_vtkWidget->renderWindow()->Render();
}