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
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

// Other Includes
#include "integration/WoWController.h"
#include <optional>
#include <string>
#include <thread>
#include <tlhelp32.h>
#include <windows.h>

// VTK Includes для конвертации
#include <vtkCellArray.h>
#include <vtkNew.h>
#include <vtkPoints.h>
#include <vtkPolyData.h>
#include <vtkSmartPointer.h>
#include <vtkTriangle.h>

// --- НОВАЯ ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ---
/**
 * @brief Конвертирует нашу внутреннюю структуру MeshData в vtkPolyData для
 * визуализации.
 * @param meshData Данные меша из нашего ObjLoader.
 * @return Умный указатель на vtkPolyData, готовый для рендера.
 */
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

// Вспомогательная функция для поиска PID (без изменений)
std::optional<DWORD> findPidByName(const std::wstring &processName) {
  PROCESSENTRY32W processInfo;
  processInfo.dwSize = sizeof(processInfo);
  HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  if (processesSnapshot == INVALID_HANDLE_VALUE)
    return std::nullopt;
  Process32FirstW(processesSnapshot, &processInfo);
  do {
    if (processName == processInfo.szExeFile) {
      CloseHandle(processesSnapshot);
      return processInfo.th32ProcessID;
    }
  } while (Process32NextW(processesSnapshot, &processInfo));
  CloseHandle(processesSnapshot);
  return std::nullopt;
}

// Конструктор (без изменений)
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
  m_pathfinder = std::make_unique<Pathfinder>();
  qInfo(lcApp) << "MainWindow created and UI is set up.";
}

// Деструктор (без изменений)
MainWindow::~MainWindow() { qInfo(lcApp) << "MainWindow destroyed."; }

// setupUi (без изменений)
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
  m_cellSizeLineEdit = new QLineEdit("1.0"); // Увеличим значение по умолчанию
  configLayout->addWidget(m_cellSizeLineEdit, 0, 1);
  m_controlPanelLayout->addLayout(configLayout);
  m_mainLayout->addWidget(m_controlPanelWidget);
  m_buildButton = new QPushButton("Выбрать .obj и Построить");
  m_controlPanelLayout->addWidget(m_buildButton);
  m_controlPanelLayout->addWidget(new QLabel("<h3>2. Работа с NavData</h3>"));
  auto *ioLayout = new QHBoxLayout();
  m_saveNavDataButton = new QPushButton("Сохранить NavData");
  m_loadNavDataButton = new QPushButton("Загрузить NavData");
  ioLayout->addWidget(m_saveNavDataButton);
  ioLayout->addWidget(m_loadNavDataButton);
  m_controlPanelLayout->addLayout(ioLayout);
  m_controlPanelLayout->addWidget(new QLabel("<h3>3. Поиск Пути</h3>"));
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

// --- ПОЛНОСТЬЮ ПЕРЕПИСАННЫЙ МЕТОД onBuildNavigation ---

void MainWindow::onBuildNavigation() {
  qInfo(lcApp) << "Button 'Build Navigation' clicked.";

  QString filePath = QFileDialog::getOpenFileName(
      this, "Выберите .obj файл", "", "OBJ Files (*.obj);;All Files (*)");

  if (filePath.isEmpty()) {
    qWarning(lcApp) << "File selection was cancelled.";
    return;
  }

  qInfo(lcApp) << "File selected for building:" << filePath;
  m_statusLabel->setText("Обработка меша...");
  QApplication::processEvents();

  m_vtkWidget->clear();
  m_navMeshGenerator.reset();

  try {
    auto meshData = ObjLoader::loadFile(filePath.toStdString());
    qInfo(lcCore) << "OBJ loaded. Vertices:" << meshData.vertices.size()
                  << " Triangles:" << meshData.indices.size();

    vtkSmartPointer<vtkPolyData> rawMeshPolyData =
        createVtkPolyDataFromMeshData(meshData);
    static const double meshColor[] = {0.6, 0.6, 0.7};
    m_vtkWidget->addMesh(rawMeshPolyData, meshColor, 0.15);
    QApplication::processEvents();

    NavMeshConfig config;
    bool ok;
    double cellSize = m_cellSizeLineEdit->text().toDouble(&ok);
    if (ok && cellSize > 0.01) {
      config.cellSize = cellSize;
    } else {
      qWarning(lcApp) << "Invalid cellSize value, using default:"
                      << config.cellSize;
      m_cellSizeLineEdit->setText(QString::number(config.cellSize));
    }

    m_navMeshGenerator = std::make_unique<NavMeshGenerator>(config);

    auto progressCallback = [this](int progress) {
      m_statusLabel->setText(QString("Обработка... %1%").arg(progress));
      QApplication::processEvents();
    };

    m_navMeshGenerator->build(meshData, progressCallback);

    qInfo(lcApp) << "Visualizing walkable areas...";

    // Получаем и рисуем проходимые места
    std::vector<Vector3d> walkableVoxels =
        m_navMeshGenerator->getWalkableVoxelCenters();
    static const double walkableColor[] = {0.2, 0.5, 1.0}; // Синий цвет
    m_vtkWidget->addPoints(walkableVoxels, walkableColor, 3.0f);

    m_vtkWidget->resetCamera();

    m_statusLabel->setText(
        QString("Найдено %1 проходимых ячеек.").arg(walkableVoxels.size()));

  } catch (const std::exception &e) {
    QString errorMsg = QString("Критическая ошибка: %1").arg(e.what());
    qCritical(lcApp) << errorMsg;
    m_statusLabel->setText(errorMsg);
  }
}

// Остальные слоты (без изменений)
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

    // Вызов остался тем же, но под капотом теперь работает 3D-логика
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
  auto pidOpt = findPidByName(L"run.exe");
  if (!pidOpt) {
    m_statusLabel->setText("Процесс Wow.exe не найден!");
    return;
  }
  WoWController controller(*pidOpt, 0x3E2E3348, 0x3E2E334C, 0x3E2E3350);
  auto pos = controller.getPlayerPosition();
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
  auto pidOpt = findPidByName(L"run.exe");
  if (!pidOpt) {
    m_statusLabel->setText("Процесс run.exe не найден!");
    return;
  }
  WoWController controller(*pidOpt, 0x3E2E3348, 0x3E2E334C, 0x3E2E3350);
  auto pos = controller.getPlayerPosition();
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
  auto pidOpt = findPidByName(L"run.exe");
  if (!pidOpt) {
    m_statusLabel->setText("Процесс Wow.exe не найден!");
    return;
  }
  std::vector<Vector3> pathForController;
  pathForController.reserve(m_currentPath.size());
  for (const auto &p : m_currentPath) {
    pathForController.push_back({(float)p.x(), (float)p.y(), (float)p.z()});
  }
  DWORD pid = *pidOpt;
  uintptr_t xAddr = 0x3E2E3348, yAddr = 0x3E2E334C, zAddr = 0x3E2E3350;
  m_statusLabel->setText("Начинаю движение...");
  std::thread([pid, xAddr, yAddr, zAddr,
               path = std::move(pathForController)]() {
    try {
      WoWController controller(pid, xAddr, yAddr, zAddr);
      controller.followPath(path);
    } catch (const std::exception &e) {
      qCritical(lcNav) << "Exception in followPath thread:" << e.what();
    }
  }).detach();
}