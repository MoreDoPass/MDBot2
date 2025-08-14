#include "Voxelizer.h"
#include "shared/Logger.h"

// --- VTK Includes ---
#include <vtkAppendPolyData.h> // Для "склеивания" проходимых полигонов
#include <vtkCell.h>
#include <vtkCellArray.h> // Для создания геометрии
#include <vtkCellData.h>
#include <vtkCellLocator.h> // Наш инструмент для рейкастинга
#include <vtkGenericCell.h> // <-- НОВЫЙ INCLUDE: нужен для получения деталей пересечения
#include <vtkIdList.h>
#include <vtkIdTypeArray.h> // Для хранения ID оригинальных полигонов
#include <vtkMath.h>
#include <vtkNew.h>
#include <vtkOBJReader.h>
#include <vtkPointData.h>
#include <vtkPoints.h> // Для создания геометрии
#include <vtkPolyData.h>
#include <vtkPolyDataNormals.h> // Для вычисления нормалей

Voxelizer::Voxelizer(const std::string &meshPath)
    : m_meshPath(meshPath), m_rawMesh(vtkSmartPointer<vtkPolyData>::New()),
      m_locator(vtkSmartPointer<vtkCellLocator>::New()),
      m_walkableMesh(vtkSmartPointer<vtkPolyData>::New()) {
  qInfo(lcCore) << "Voxelizer created for mesh:"
                << QString::fromStdString(m_meshPath);
}

bool Voxelizer::build() {
  qInfo(lcCore) << "NavMeshGenerator build process started for"
                << QString::fromStdString(m_meshPath);

  try {
    // --- Шаг 1: Загрузка меша ---
    vtkNew<vtkOBJReader> reader;
    reader->SetFileName(m_meshPath.c_str());
    reader->Update();
    m_rawMesh = reader->GetOutput();
    if (!m_rawMesh || m_rawMesh->GetNumberOfPoints() == 0) {
      qCritical(lcCore) << "Failed to read OBJ file or mesh is empty:"
                        << QString::fromStdString(m_meshPath);
      return false;
    }
    qInfo(lcCore) << "Mesh loaded. Polys:" << m_rawMesh->GetNumberOfPolys();

    // --- Шаг 2: Создание локатора для быстрых пересечений ---
    m_locator->SetDataSet(m_rawMesh);
    m_locator->BuildLocator();
    qInfo(lcCore) << "CellLocator built for raycasting.";

    // --- Шаг 3: Вычисление нормалей для каждого полигона ---
    vtkSmartPointer<vtkPolyData> meshWithNormals =
        vtkSmartPointer<vtkPolyData>::New();
    vtkNew<vtkPolyDataNormals> normalGenerator;
    normalGenerator->SetInputData(m_rawMesh);
    normalGenerator->ComputePointNormalsOff();
    normalGenerator->ComputeCellNormalsOn();
    normalGenerator->Update();
    meshWithNormals->DeepCopy(normalGenerator->GetOutput());
    vtkDataArray *cellNormals = meshWithNormals->GetCellData()->GetNormals();
    if (!cellNormals) {
      qCritical(lcCore) << "Failed to compute cell normals.";
      return false;
    }

    // --- Шаг 4: Фильтрация проходимых полигонов с ИСПРАВЛЕННОЙ проверкой
    // высоты ---
    vtkNew<vtkAppendPolyData> appendFilter;
    vtkNew<vtkIdTypeArray> originalIds;
    originalIds->SetName("OriginalCellIds");

    const double z_axis[3] = {0.0, 0.0, 1.0};
    const double agentHeight =
        2.0; // Высота персонажа (увеличил для надежности)
    const double raycastOffset =
        0.1; // Небольшой отступ от пола, чтобы луч не пересек сам себя
    const double maxSlopeAngle = 45.0; // Максимальный угол уклона
    const double maxSlopeDot = cos(vtkMath::RadiansFromDegrees(maxSlopeAngle));

    for (vtkIdType i = 0; i < meshWithNormals->GetNumberOfCells(); ++i) {
      // --- Фильтр по углу ---
      double normal[3];
      cellNormals->GetTuple(i, normal);
      if (vtkMath::Dot(normal, z_axis) < maxSlopeDot) {
        continue; // Слишком крутой уклон, пропускаем
      }

      // --- Находим центр полигона ---
      vtkCell *cell = meshWithNormals->GetCell(i);
      vtkIdList *pointIds = cell->GetPointIds();
      double center[3] = {0.0, 0.0, 0.0};
      int numPoints = pointIds->GetNumberOfIds();
      if (numPoints == 0)
        continue;

      for (vtkIdType j = 0; j < numPoints; ++j) {
        double p[3];
        meshWithNormals->GetPoint(pointIds->GetId(j), p);
        center[0] += p[0];
        center[1] += p[1];
        center[2] += p[2];
      }
      center[0] /= numPoints;
      center[1] /= numPoints;
      center[2] /= numPoints;

      // --- ИСПРАВЛЕННЫЙ Фильтр по высоте (рейкастинг) ---
      double rayStart[3] = {center[0], center[1], center[2] + raycastOffset};
      // Пускаем луч далеко вверх, чтобы гарантированно пересечь потолок, если
      // он есть
      double rayEnd[3] = {center[0], center[1],
                          center[2] + raycastOffset + agentHeight + 100.0};

      // Переменные для получения детальной информации о пересечении
      double intersectionT;        // "Время" пересечения луча (доля длины)
      double intersectionPoint[3]; // Координаты точки пересечения
      double pcoords[3];           // Параметрические координаты внутри ячейки
      int subId;                   // ID подъячейки
      vtkIdType intersectedCellId; // ID полигона, который мы пересекли

      // vtkGenericCell используется для получения полной информации о ячейке, с
      // которой произошло пересечение
      vtkNew<vtkGenericCell> intersectedCell;

      // Выполняем рейкаст. Эта версия функции возвращает 1, если пересечение
      // было, и 0, если нет.
      int hit = m_locator->IntersectWithLine(
          rayStart, rayEnd, 0.001, intersectionT, intersectionPoint, pcoords,
          subId, intersectedCellId, intersectedCell.GetPointer());

      bool isWalkable = false;
      if (hit == 0) {
        // Случай 1: Луч ничего не пересек (открытое небо). Это точно проходимое
        // место.
        isWalkable = true;
        // qDebug(lcCore) << "Cell" << i << "is walkable (open sky)"; //
        // Раскомментируй для детальной отладки
      } else {
        // Случай 2: Луч что-то пересек. Нам нужно проверить, достаточно ли до
        // этого объекта места.
        double distance =
            vtkMath::Distance2BetweenPoints(rayStart, intersectionPoint);
        // Сравниваем квадрат расстояния, это чуть быстрее, чем извлекать корень
        if (distance > (agentHeight * agentHeight)) {
          // Расстояние до потолка больше высоты агента. Проходимо.
          isWalkable = true;
          // qDebug(lcCore) << "Cell" << i << "is walkable (high ceiling,
          // dist^2=" << distance << ")";
        } else {
          // qDebug(lcCore) << "Cell" << i << "is NOT walkable (low ceiling,
          // dist^2=" << distance << ")";
        }
      }

      if (isWalkable) {
        // --- Копируем проходимый полигон ---
        // Эта часть кода не изменилась
        vtkNew<vtkPolyData> singlePolygon;
        vtkNew<vtkPoints> points;
        vtkNew<vtkCellArray> cellArray;

        vtkCell *originalCell = meshWithNormals->GetCell(i);
        vtkIdList *originalPointIds = originalCell->GetPointIds();
        vtkNew<vtkIdList> newPointIds;

        for (vtkIdType p = 0; p < originalPointIds->GetNumberOfIds(); ++p) {
          vtkIdType pointId = originalPointIds->GetId(p);
          points->InsertNextPoint(meshWithNormals->GetPoint(pointId));
          newPointIds->InsertNextId(p);
        }

        cellArray->InsertNextCell(newPointIds);
        singlePolygon->SetPoints(points);
        singlePolygon->SetPolys(cellArray);

        appendFilter->AddInputData(singlePolygon);
        originalIds->InsertNextValue(i);
      }
    }

    if (appendFilter->GetNumberOfInputConnections(0) > 0) {
      appendFilter->Update();
      m_walkableMesh = appendFilter->GetOutput();
      m_walkableMesh->GetCellData()->AddArray(originalIds);
    } else {
      // Важно обработать случай, когда ВООБЩЕ не найдено проходимых полигонов
      qWarning(lcCore) << "No walkable polygons were found after filtering. "
                          "The resulting navmesh will be empty.";
      m_walkableMesh->Initialize(); // Создаем пустой, но валидный vtkPolyData
    }

    qInfo(lcCore) << "Found" << m_walkableMesh->GetNumberOfCells()
                  << "walkable polygons.";
    return true;
  } catch (const std::exception &e) {
    qCritical(lcCore) << "An exception occurred in Voxelizer::build(): "
                      << e.what();
    return false;
  }
}

vtkSmartPointer<vtkPolyData> Voxelizer::getWalkableMesh() const {
  return m_walkableMesh;
}

vtkSmartPointer<vtkPolyData> Voxelizer::getRawMesh() const { return m_rawMesh; }