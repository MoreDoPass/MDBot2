#pragma once

#include "core/generator/NavMeshGenerator.h" // Включаем для enum
#include "core/math/Types.h"
#include <QMainWindow>
#include <memory>
#include <vtkPolyData.h>
#include <vtkSmartPointer.h>

// #include <vtkKDTree.h>      // Эти два инклюда тут больше не нужны
// #include <vtkSmartPointer.h>

// Вперед объявляем классы, которые будем использовать.
class QPushButton;
class QLineEdit;
class QTextEdit;
class QLabel;
class QVBoxLayout;
class QHBoxLayout;
class QGridLayout;
class VtkWidget;
class Pathfinder;
class NavMeshGenerator; // Оставляем прямое объявление, это хороший стиль
class WoWController;
class QGroupBox;    // <-- Новое
class QRadioButton; // <-- Новое

/**
 * @class MainWindow
 * @brief Главное окно приложения, содержит все элементы управления.
 */
class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  explicit MainWindow(QWidget *parent = nullptr);
  ~MainWindow();

private slots:
  void onBuildNavigation();
  void onSaveNavData();
  void onLoadNavData();
  void onGetStartPosition();
  void onGetEndPosition();
  void onFindPath();
  void onRunInWoW();

  /**
   * @brief Слот, вызываемый при изменении выбора в группе отладки.
   */
  void onDebugVoxelViewChanged();

private:
  void setupUi();
  void updateVoxelVisualization(NavMeshGenerator::VoxelizationStage stage);

  // ... указатели на виджеты ...
  VtkWidget *m_vtkWidget = nullptr;
  QWidget *m_centralWidget = nullptr;
  QHBoxLayout *m_mainLayout = nullptr;
  QWidget *m_controlPanelWidget = nullptr;
  QVBoxLayout *m_controlPanelLayout = nullptr;
  QPushButton *m_buildButton = nullptr;
  QPushButton *m_saveNavDataButton = nullptr;
  QPushButton *m_loadNavDataButton = nullptr;
  QPushButton *m_getStartButton = nullptr;
  QPushButton *m_getEndButton = nullptr;
  QPushButton *m_findPathButton = nullptr;
  QPushButton *m_runInWoWButton = nullptr;
  QLineEdit *m_startLineEdit = nullptr;
  QLineEdit *m_cellSizeLineEdit = nullptr;
  QLineEdit *m_cellHeightLineEdit = nullptr;
  QLineEdit *m_agentRadiusLineEdit = nullptr;
  QLineEdit *m_endLineEdit = nullptr;
  QLineEdit *m_baseAddressLineEdit = nullptr;
  QTextEdit *m_pathOutputTextEdit = nullptr;
  QLabel *m_statusLabel = nullptr;

  // --- Новые виджеты для отладки ---
  QGroupBox *m_debugViewGroup = nullptr;
  QRadioButton *m_radioDebugSolid = nullptr;
  QRadioButton *m_radioDebugFloors = nullptr;
  QRadioButton *m_radioDebugHeight = nullptr;
  QRadioButton *m_radioDebugFinal = nullptr;

  std::unique_ptr<WoWController> connectToWoW();

  // --- Указатели на наши движки ---
  std::unique_ptr<Pathfinder> m_pathfinder;
  std::unique_ptr<NavMeshGenerator> m_navMeshGenerator;

  // --- Старые данные, которые нужно будет переделать ---
  // std::vector<Vector3d> m_walkablePoints;
  // vtkSmartPointer<vtkKdTree> m_kdTree;
  std::vector<Vector3d> m_currentPath;

  /// @brief Указатель на полигональные данные меша, чтобы не пересоздавать их.
  vtkSmartPointer<vtkPolyData> m_rawMeshPolyData;
};