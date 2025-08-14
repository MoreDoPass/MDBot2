#include "NavGraph.h"
#include "shared/Logger.h"

// VTK includes
#include <vtkCell.h>
#include <vtkCellLocator.h>
#include <vtkCleanPolyData.h>
#include <vtkGenericCell.h> // <-- НУЖЕН для FindClosestPoint
#include <vtkIdList.h>
#include <vtkMath.h>
#include <vtkNew.h>
#include <vtkPolyData.h>

NavGraph::NavGraph() {}

void NavGraph::build(vtkSmartPointer<vtkPolyData> walkablePolys,
                     double maxStepHeight) {
  qInfo(lcCore) << "Building navigation graph...";

  if (!walkablePolys || walkablePolys->GetNumberOfCells() == 0) {
    qWarning(lcCore) << "Walkable mesh is empty, cannot build graph.";
    return;
  }

  // --- Шаг 0: Очистка меша все еще полезна, чтобы убрать явные дубликаты ---
  vtkNew<vtkCleanPolyData> cleaner;
  cleaner->SetInputData(walkablePolys);
  cleaner->SetTolerance(0.01); // Можно использовать небольшую толерантность
  cleaner->Update();
  vtkSmartPointer<vtkPolyData> cleanedMesh = cleaner->GetOutput();
  qInfo(lcCore) << "Mesh cleaned. Polys before:"
                << walkablePolys->GetNumberOfCells()
                << ", Polys after:" << cleanedMesh->GetNumberOfCells();

  const int numPolys = cleanedMesh->GetNumberOfCells();
  if (numPolys == 0) {
    qWarning(lcCore) << "Cleaned mesh is empty.";
    return;
  }

  m_nodes.resize(numPolys);
  m_adj.assign(numPolys, {});

  // --- Шаг 1: Находим и сохраняем центры всех полигонов ---
  for (int i = 0; i < numPolys; ++i) {
    vtkCell *cell = cleanedMesh->GetCell(i);
    double bounds[6];
    cell->GetBounds(bounds); // Получаем границы ячейки
    // Используем центр bounding box'а, это стабильнее для невыпуклых полигонов
    double center[3] = {(bounds[0] + bounds[1]) / 2.0,
                        (bounds[2] + bounds[3]) / 2.0,
                        (bounds[4] + bounds[5]) / 2.0};
    m_nodes[i] = {center[0], center[1], center[2]};
  }
  qInfo(lcCore) << "Graph nodes (polygon centers) created:" << m_nodes.size();

  // --- НОВЫЙ Шаг 2: Строим связи между соседями через ГЕОМЕТРИЧЕСКИЙ поиск ---

  // Создаем локатор для нашего проходимого меша, чтобы быстро находить полигоны
  // по координатам
  vtkNew<vtkCellLocator> locator;
  locator->SetDataSet(cleanedMesh);
  locator->BuildLocator();

  int edgeCount = 0;

  for (int cellId = 0; cellId < numPolys; ++cellId) {
    vtkCell *cell = cleanedMesh->GetCell(cellId);
    int numEdges = cell->GetNumberOfEdges();

    // Перебираем все ребра (грани) текущего полигона
    for (int edgeIdx = 0; edgeIdx < numEdges; ++edgeIdx) {
      vtkCell *edge = cell->GetEdge(edgeIdx);
      if (edge->GetNumberOfPoints() != 2)
        continue; // Нас интересуют только ребра-линии

      // Находим среднюю точку ребра
      double p1[3], p2[3];
      cleanedMesh->GetPoint(edge->GetPointId(0), p1);
      cleanedMesh->GetPoint(edge->GetPointId(1), p2);
      double edgeMidPoint[3] = {(p1[0] + p2[0]) / 2.0, (p1[1] + p2[1]) / 2.0,
                                (p1[2] + p2[2]) / 2.0};

      // --- ИСПРАВЛЕНИЕ: Используем FindClosestPoint вместо FindClosestCell ---
      double
          closestPoint[3]; // Сюда будет записана ближайшая точка на поверхности
      vtkNew<vtkGenericCell>
          foundCell;         // Сюда будет записана информация о ячейке
      vtkIdType foundCellId; // Сюда будет записан ID найденной ячейки
      int subId;    // Вспомогательная переменная, обязательна для вызова
      double dist2; // Сюда будет записан квадрат расстояния

      locator->FindClosestPoint(edgeMidPoint, closestPoint,
                                foundCell.GetPointer(), foundCellId, subId,
                                dist2);

      // Проверяем, что найденный полигон - это не мы сами, и он действительно
      // рядом (сосед)
      if (foundCellId != cellId &&
          dist2 < 0.1) { // 0.1 - допуск, можно подбирать
        // Проверяем высоту шага
        const double heightDiff =
            abs(m_nodes[cellId].z() - m_nodes[foundCellId].z());
        if (heightDiff <= maxStepHeight) {
          // Добавляем связь. Чтобы избежать дублей, проверяем, есть ли уже
          // такая связь
          bool alreadyConnected = false;
          for (int neighbor : m_adj[cellId]) {
            if (neighbor == foundCellId) {
              alreadyConnected = true;
              break;
            }
          }
          if (!alreadyConnected) {
            m_adj[cellId].push_back(foundCellId);
            // Так как граф неориентированный, добавляем и обратную связь
            m_adj[foundCellId].push_back(cellId);
            edgeCount++;
          }
        }
      }
    }
  }
  // Так как мы добавляли ребра в обе стороны, делим итоговое количество на 2
  // для статистики
  qInfo(lcCore) << "Graph edges (connections) created:" << (edgeCount);
}

const std::vector<Vector3d> &NavGraph::getNodes() const { return m_nodes; }

const AdjacencyList &NavGraph::getAdjacencyList() const { return m_adj; }