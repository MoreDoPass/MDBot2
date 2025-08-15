#include "MainWindow.h"
#include "core/generator/NavMeshGenerator.h"
#include "core/loader/ObjLoader.h"
#include "core/pathfinder/Pathfinder.h"
#include "gui/VtkWidget.h"
#include "shared/Logger.h"

// Qt Includes
#include <QApplication>
#include <QFileDialog>
#include <QGridLayout>
#include <QGroupBox> // <-- Новое
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton> // <-- Новое
#include <QTextEdit>
#include <QVBoxLayout>

// Other Includes
#include "integration/WoWController.h"
#include <optional>
#include <string>
#include <thread>

// VTK Includes для конвертации
#include <vtkCellArray.h>
#include <vtkNew.h>
#include <vtkPoints.h>
#include <vtkPolyData.h>
#include <vtkSmartPointer.h>
#include <vtkTriangle.h>

// --- НОВАЯ ХЕЛПЕР-ФУНКЦИЯ ---
/**
 * @brief Конвертирует VoxelGrid в вектор мировых координат центров вокселей.
 * @param grid Входная воксельная сетка.
 * @param generator Указатель на генератор, который знает, как конвертировать
 *                  координаты из сетки в мировые.
 * @return Вектор 3D точек.
 */
std::vector<Vector3d>
getVoxelCentersFromGrid(const VoxelGrid &grid,
                        const NavMeshGenerator *generator) {
  std::vector<Vector3d> centers;
  if (grid.solidVoxels.empty() || !generator) {
    return centers;
  }
  centers.reserve(grid.solidVoxels.size() / 20);

  for (int y = 0; y < grid.gridHeight; ++y) {
    for (int z = 0; z < grid.gridDepth; ++z) {
      for (int x = 0; x < grid.gridWidth; ++x) {
        if (grid.solidVoxels[grid.getVoxelIndex(x, y, z)]) {
          centers.push_back(generator->gridToWorld(x, y, z));
        }
      }
    }
  }
  return centers;
}

vtkSmartPointer<vtkPolyData>
createVtkPolyDataFromMeshData(const MeshData &meshData) {
  vtkNew<vtkPoints> points;
  points->Allocate(meshData.vertices.size());
  for (const auto &v : meshData.vertices) {
    points->InsertNextPoint(v.x(), v.y(), v.z());
  }

  vtkNew<vtkCellArray> triangles;
  triangles->Allocate(meshData.indices.size());
  for (const auto &idx : meshData.indices) {
    vtkNew<vtkTriangle> triangle;
    triangle->GetPointIds()->SetId(0, idx[0]);
    triangle->GetPointIds()->SetId(1, idx[1]);
    triangle->GetPointIds()->SetId(2, idx[2]);
    triangles->InsertNextCell(triangle);
  }

  vtkSmartPointer<vtkPolyData> polyData = vtkSmartPointer<vtkPolyData>::New();
  polyData->SetPoints(points);
  polyData->SetPolys(triangles);

  return polyData;
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  setupUi();
  connect(m_buildButton, &QPushButton::clicked, this,
          &MainWindow::onBuildNavigation);
  connect(m_saveNavDataButton, &QPushButton::clicked, this,
          &MainWindow::onSaveNavData);
  connect(m_loadNavDataButton, &QPushButton::clicked, this,
          &MainWindow::onLoadNavData);
  connect(m_getStartButton, &QPushButton::clicked, this,
          &MainWindow::onGetStartPosition);
  connect(m_getEndButton, &QPushButton::clicked, this,
          &MainWindow::onGetEndPosition);
  connect(m_findPathButton, &QPushButton::clicked, this,
          &MainWindow::onFindPath);
  connect(m_runInWoWButton, &QPushButton::clicked, this,
          &MainWindow::onRunInWoW);

  // --- НОВЫЕ CONNECT'Ы ДЛЯ ОТЛАДКИ ---
  connect(m_radioDebugSolid, &QRadioButton::toggled, this,
          &MainWindow::onDebugVoxelViewChanged);
  connect(m_radioDebugFloors, &QRadioButton::toggled, this,
          &MainWindow::onDebugVoxelViewChanged);
  connect(m_radioDebugHeight, &QRadioButton::toggled, this,
          &MainWindow::onDebugVoxelViewChanged);
  connect(m_radioDebugFinal, &QRadioButton::toggled, this,
          &MainWindow::onDebugVoxelViewChanged);

  m_pathfinder = std::make_unique<Pathfinder>();
  qInfo(lcApp) << "MainWindow created and UI is set up.";
}

MainWindow::~MainWindow() { qInfo(lcApp) << "MainWindow destroyed."; }

void MainWindow::setupUi() {
  setWindowTitle("WoW Navigator (C++)");
  setGeometry(100, 100, 1400, 900);
  m_centralWidget = new QWidget(this);
  setCentralWidget(m_centralWidget);
  m_mainLayout = new QHBoxLayout(m_centralWidget);
  m_vtkWidget = new VtkWidget();
  m_mainLayout->addWidget(m_vtkWidget, 1);
  m_controlPanelWidget = new QWidget();
  m_controlPanelWidget->setFixedWidth(350);
  m_controlPanelLayout = new QVBoxLayout(m_controlPanelWidget);
  m_controlPanelLayout->addWidget(new QLabel("<h3>1. Построение Карты</h3>"));
  auto *configLayout = new QGridLayout();

  configLayout->addWidget(new QLabel("Размер вокселя (cellSize):"), 0, 0);
  m_cellSizeLineEdit = new QLineEdit("0.3");
  configLayout->addWidget(m_cellSizeLineEdit, 0, 1);
  configLayout->addWidget(new QLabel("Высота вокселя (cellHeight):"), 1, 0);
  m_cellHeightLineEdit = new QLineEdit("0.2");
  configLayout->addWidget(m_cellHeightLineEdit, 1, 1);

  // --- НОВОЕ ПОЛЕ В ИНТЕРФЕЙСЕ ---
  configLayout->addWidget(new QLabel("Радиус агента (agentRadius):"), 2, 0);
  m_agentRadiusLineEdit = new QLineEdit("0.6");
  configLayout->addWidget(m_agentRadiusLineEdit, 2, 1);
  // ------------------------------------

  m_controlPanelLayout->addLayout(configLayout);
  m_mainLayout->addWidget(m_controlPanelWidget);
  m_buildButton = new QPushButton("Выбрать .obj и Построить");
  m_controlPanelLayout->addWidget(m_buildButton);

  // --- НОВЫЙ БЛОК ДЛЯ ОТЛАДКИ ---
  m_debugViewGroup = new QGroupBox("Voxel Debug View");
  auto *debugLayout = new QVBoxLayout();
  m_radioDebugSolid = new QRadioButton("Этап 1: Solid Geometry");
  m_radioDebugFloors = new QRadioButton("Этап 2: Potential Floors");
  m_radioDebugHeight = new QRadioButton("Этап 3: Height Filtered");
  m_radioDebugFinal = new QRadioButton("Этап 4: Final Walkable");
  debugLayout->addWidget(m_radioDebugSolid);
  debugLayout->addWidget(m_radioDebugFloors);
  debugLayout->addWidget(m_radioDebugHeight);
  debugLayout->addWidget(m_radioDebugFinal);
  m_debugViewGroup->setLayout(debugLayout);
  m_controlPanelLayout->addWidget(m_debugViewGroup);
  m_radioDebugFinal->setChecked(
      true); // По умолчанию показываем финальный результат
  m_debugViewGroup->setEnabled(false); // Выключен до первой успешной сборки
  // -----------------------------

  m_controlPanelLayout->addWidget(new QLabel("<h3>2. Работа с NavData</h3>"));
  auto *ioLayout = new QHBoxLayout();
  m_saveNavDataButton = new QPushButton("Сохранить NavData");
  m_loadNavDataButton = new QPushButton("Загрузить NavData");
  ioLayout->addWidget(m_saveNavDataButton);
  ioLayout->addWidget(m_loadNavDataButton);
  m_controlPanelLayout->addLayout(ioLayout);
  m_controlPanelLayout->addWidget(new QLabel("<h3>3. Поиск Пути</h3>"));

  auto *wowLayout = new QGridLayout();
  wowLayout->addWidget(new QLabel("Базовый адрес XYZ:"), 0, 0);
  m_baseAddressLineEdit = new QLineEdit("0x3E2E3348");
  wowLayout->addWidget(m_baseAddressLineEdit, 0, 1);
  m_controlPanelLayout->addLayout(wowLayout);
  auto *formLayout = new QGridLayout();
  m_getStartButton = new QPushButton("Взять Старт (из игры)");
  m_startLineEdit = new QLineEdit("...");
  m_startLineEdit->setReadOnly(true);
  m_getEndButton = new QPushButton("Взять Финиш (из игры)");
  m_endLineEdit = new QLineEdit("...");
  m_endLineEdit->setReadOnly(true);
  formLayout->addWidget(m_getStartButton, 0, 0);
  formLayout->addWidget(m_startLineEdit, 0, 1);
  formLayout->addWidget(m_getEndButton, 1, 0);
  formLayout->addWidget(m_endLineEdit, 1, 1);
  m_controlPanelLayout->addLayout(formLayout);
  m_findPathButton = new QPushButton("Найти Путь");
  m_controlPanelLayout->addWidget(m_findPathButton);
  m_runInWoWButton = new QPushButton("Двигаться в WoW");
  m_controlPanelLayout->addWidget(m_runInWoWButton);
  m_controlPanelLayout->addWidget(new QLabel("<h3>Найденный путь</h3>"));
  m_pathOutputTextEdit = new QTextEdit();
  m_pathOutputTextEdit->setReadOnly(true);
  m_controlPanelLayout->addWidget(m_pathOutputTextEdit);
  m_controlPanelLayout->addStretch();
  m_statusLabel = new QLabel("Ожидание...");
  m_statusLabel->setWordWrap(true);
  m_controlPanelLayout->addWidget(m_statusLabel);
}

void MainWindow::onBuildNavigation() {
  qInfo(lcApp) << "Button 'Build Navigation' clicked.";
  QString filePath = QFileDialog::getOpenFileName(
      this, "Select .obj file", "", "OBJ Files (*.obj);;All Files (*)");
  if (filePath.isEmpty()) {
    qWarning(lcApp) << "File selection was cancelled.";
    return;
  }
  qInfo(lcApp) << "File selected for building:" << filePath;
  m_statusLabel->setText("Processing mesh...");

  // Перед сборкой отключаем панель отладки
  m_debugViewGroup->setEnabled(false);
  QApplication::processEvents();

  m_vtkWidget->clear();
  m_navMeshGenerator.reset();
  m_rawMeshPolyData = nullptr;

  try {
    auto meshData = ObjLoader::loadFile(filePath.toStdString());

    m_rawMeshPolyData = createVtkPolyDataFromMeshData(meshData);
    static const double meshColor[] = {0.6, 0.6, 0.7};
    m_vtkWidget->addMesh(m_rawMeshPolyData, meshColor, 0.15);
    QApplication::processEvents();

    NavMeshConfig config;
    bool ok_size, ok_height, ok_radius;

    double cellSize = m_cellSizeLineEdit->text().toDouble(&ok_size);
    if (ok_size && cellSize > 0.01) {
      config.cellSize = cellSize;
    } else { /* ... (валидация) ... */
    }

    double cellHeight = m_cellHeightLineEdit->text().toDouble(&ok_height);
    if (ok_height && cellHeight > 0.01) {
      config.cellHeight = cellHeight;
    } else { /* ... (валидация) ... */
    }

    double agentRadius = m_agentRadiusLineEdit->text().toDouble(&ok_radius);
    if (ok_radius && agentRadius > 0.0) {
      config.agentRadius = agentRadius;
    } else { /* ... (валидация) ... */
    }

    m_navMeshGenerator = std::make_unique<NavMeshGenerator>(config);
    if (!m_navMeshGenerator->build(meshData)) {
      m_statusLabel->setText("Ошибка построения NavMesh. См. лог.");
      qCritical(lcApp) << "NavMeshGenerator::build() returned false.";
      return;
    }

    // После успешной сборки включаем панель отладки
    m_debugViewGroup->setEnabled(true);
    // И показываем финальный результат по умолчанию
    updateVoxelVisualization(
        NavMeshGenerator::VoxelizationStage::FinalWalkable);

    m_vtkWidget->resetCamera();

  } catch (const std::exception &e) {
    QString errorMsg = QString("Critical error during build: %1").arg(e.what());
    qCritical(lcApp) << errorMsg;
    m_statusLabel->setText(errorMsg);
  }
}

void MainWindow::onDebugVoxelViewChanged() {
  // Этот слот вызывается для всех радио-кнопок, но нам нужно реагировать
  // только на ту, которая стала активной.
  QRadioButton *source = qobject_cast<QRadioButton *>(sender());
  if (!source || !source->isChecked()) {
    return; // Ничего не делаем, если сигнал пришел от выключенной кнопки
  }

  if (m_radioDebugSolid->isChecked()) {
    updateVoxelVisualization(NavMeshGenerator::VoxelizationStage::Solid);
  } else if (m_radioDebugFloors->isChecked()) {
    updateVoxelVisualization(
        NavMeshGenerator::VoxelizationStage::WalkableFloors);
  } else if (m_radioDebugHeight->isChecked()) {
    updateVoxelVisualization(
        NavMeshGenerator::VoxelizationStage::HeightFiltered);
  } else if (m_radioDebugFinal->isChecked()) {
    updateVoxelVisualization(
        NavMeshGenerator::VoxelizationStage::FinalWalkable);
  }
}

void MainWindow::updateVoxelVisualization(
    NavMeshGenerator::VoxelizationStage stage) {
  if (!m_navMeshGenerator) {
    qWarning(lcApp)
        << "Attempted to update voxel view, but NavMeshGenerator is null.";
    return;
  }
  qInfo(lcApp) << "Updating voxel visualization for stage:"
               << static_cast<int>(stage);

  // Получаем нужную сетку из генератора
  const VoxelGrid &grid = m_navMeshGenerator->getDebugVoxelGrid(stage);

  // Конвертируем ее в точки
  std::vector<Vector3d> centers =
      getVoxelCentersFromGrid(grid, m_navMeshGenerator.get());

  // Задаем цвет в зависимости от этапа
  static const double solidColor[] = {0.8, 0.2, 0.2}; // Красный для препятствий
  static const double floorColor[] = {0.8, 0.8, 0.2}; // Желтый для полов
  static const double heightColor[] = {0.2, 0.8, 0.2}; // Зеленый для высоты
  static const double finalColor[] = {0.2, 0.5, 1.0};  // Синий для финала

  const double *color = finalColor;
  QString statusText =
      QString("Этап 4: Финальная сетка. Точек: %1").arg(centers.size());

  switch (stage) {
  case NavMeshGenerator::VoxelizationStage::Solid:
    color = solidColor;
    statusText =
        QString("Этап 1: Solid Geometry. Точек: %1").arg(centers.size());
    break;
  case NavMeshGenerator::VoxelizationStage::WalkableFloors:
    color = floorColor;
    statusText =
        QString("Этап 2: Potential Floors. Точек: %1").arg(centers.size());
    break;
  case NavMeshGenerator::VoxelizationStage::HeightFiltered:
    color = heightColor;
    statusText =
        QString("Этап 3: Height Filtered. Точек: %1").arg(centers.size());
    break;
  case NavMeshGenerator::VoxelizationStage::FinalWalkable:
    // Уже установлено по умолчанию
    break;
  }

  // Обновляем виджет VTK
  m_vtkWidget->addPoints(centers, color, 3.0f);
  m_statusLabel->setText(statusText);
}

// ... остальные слоты (connectToWoW, onFindPath и т.д.) остаются без изменений
// ...
std::unique_ptr<WoWController> MainWindow::connectToWoW() {
  QString addrText = m_baseAddressLineEdit->text();
  uintptr_t baseAddr = 0;
  bool ok;
  if (addrText.startsWith("0x", Qt::CaseInsensitive)) {
    baseAddr = addrText.mid(2).toULongLong(&ok, 16);
  } else {
    baseAddr = addrText.toULongLong(&ok, 10);
  }

  if (!ok) {
    m_statusLabel->setText("Ошибка: неверный формат адреса.");
    return nullptr;
  }

  auto controller = WoWController::findAndConnect(L"run.exe", baseAddr);
  if (!controller) {
    m_statusLabel->setText("Ошибка: не удалось подключиться к процессу.");
    return nullptr;
  }

  m_statusLabel->setText("Подключено к процессу WoW.");
  return controller;
}

void MainWindow::onSaveNavData() {
  qInfo(lcApp) << "Button 'Save NavData' clicked.";
}
void MainWindow::onLoadNavData() {
  qInfo(lcApp) << "Button 'Load NavData' clicked.";
}

void MainWindow::onFindPath() {
  if (!m_navMeshGenerator) {
    m_statusLabel->setText("Сначала постройте навигацию!");
    return;
  }

  QString startText = m_startLineEdit->text();
  QString endText = m_endLineEdit->text();
  QStringList startParts = startText.split(',');
  QStringList endParts = endText.split(',');

  if (startParts.size() != 3 || endParts.size() != 3) {
    m_statusLabel->setText("Заполните координаты Старт и Финиш.");
    return;
  }

  try {
    Vector3d startPos(startParts[0].toDouble(), startParts[1].toDouble(),
                      startParts[2].toDouble());
    Vector3d endPos(endParts[0].toDouble(), endParts[1].toDouble(),
                    endParts[2].toDouble());

    qInfo(lcApp) << "Finding path from" << startPos.x() << startPos.y()
                 << startPos.z() << "to" << endPos.x() << endPos.y()
                 << endPos.z();

    auto pathResult =
        m_pathfinder->findPath(m_navMeshGenerator.get(), startPos, endPos);

    if (pathResult) {
      m_currentPath = *pathResult;
      m_statusLabel->setText(
          QString("Путь найден! Точек: %1").arg(m_currentPath.size()));

      m_vtkWidget->addPath(m_currentPath);

      QString pathStr;
      for (const auto &p : m_currentPath) {
        pathStr += QString("[%1, %2, %3]\n")
                       .arg(p.x(), 0, 'f', 1)
                       .arg(p.y(), 0, 'f', 1)
                       .arg(p.z(), 0, 'f', 1);
      }
      m_pathOutputTextEdit->setText(pathStr);
    } else {
      m_statusLabel->setText("Путь не найден.");
      m_currentPath.clear();
      m_pathOutputTextEdit->clear();
    }

  } catch (const std::exception &e) {
    qCritical(lcApp) << "Error during pathfinding:" << e.what();
    m_statusLabel->setText("Ошибка при поиске пути.");
  }
}

void MainWindow::onGetStartPosition() {
  auto controller = connectToWoW();
  if (!controller)
    return;

  auto pos = controller->getPlayerPosition();
  if (pos) {
    m_startLineEdit->setText(QString("%1, %2, %3")
                                 .arg(pos->x, 0, 'f', 2)
                                 .arg(pos->y, 0, 'f', 2)
                                 .arg(pos->z, 0, 'f', 2));
  } else {
    m_statusLabel->setText("Не удалось получить позицию.");
  }
}

void MainWindow::onGetEndPosition() {
  auto controller = connectToWoW();
  if (!controller)
    return;

  auto pos = controller->getPlayerPosition();
  if (pos) {
    m_endLineEdit->setText(QString("%1, %2, %3")
                               .arg(pos->x, 0, 'f', 2)
                               .arg(pos->y, 0, 'f', 2)
                               .arg(pos->z, 0, 'f', 2));
  } else {
    m_statusLabel->setText("Не удалось получить позицию.");
  }
}

void MainWindow::onRunInWoW() {
  if (m_currentPath.empty()) {
    m_statusLabel->setText("Сначала найдите путь!");
    return;
  }

  auto controller = connectToWoW();
  if (!controller)
    return;

  std::vector<Vector3> pathForController;
  pathForController.reserve(m_currentPath.size());
  for (const auto &p : m_currentPath) {
    pathForController.push_back({(float)p.x(), (float)p.y(), (float)p.z()});
  }

  m_statusLabel->setText("Начинаю движение...");

  std::thread([controller = std::move(controller),
               path = std::move(pathForController)]() {
    try {
      controller->followPath(path);
    } catch (const std::exception &e) {
      qCritical(lcNav) << "Exception in followPath thread:" << e.what();
    }
  }).detach();
}