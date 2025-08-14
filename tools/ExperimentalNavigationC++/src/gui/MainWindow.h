#pragma once

#include "core/math/Types.h"
#include <QMainWindow>
#include <memory>
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

private:
  void setupUi();

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
  QLineEdit *m_endLineEdit = nullptr;
  QTextEdit *m_pathOutputTextEdit = nullptr;
  QLabel *m_statusLabel = nullptr;

  // --- Указатели на наши движки ---
  std::unique_ptr<Pathfinder> m_pathfinder;
  std::unique_ptr<NavMeshGenerator> m_navMeshGenerator;

  // --- Старые данные, которые нужно будет переделать ---
  // std::vector<Vector3d> m_walkablePoints;
  // vtkSmartPointer<vtkKdTree> m_kdTree;
  std::vector<Vector3d> m_currentPath;
};