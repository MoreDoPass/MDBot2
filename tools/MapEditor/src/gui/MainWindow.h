#pragma once

#include <QMainWindow>
#include <QPushButton>
#include <QHBoxLayout>  // Для компоновки кнопок
#include <QVBoxLayout>  // Для основной компоновки
#include <QSpacerItem>  // Для разделителя
#include <QWidget>      // Для центрального виджета
#include <QTimer>
#include <QMenu>     // Для меню
#include <QAction>   // Для действий в меню
#include <QMenuBar>  // Для строки меню
#include <QObject>   // Добавлено для Q_OBJECT и слотов
#include <QString>   // Добавлено для QString
#include <QVector3D>
#include <QList>
#include <QSet>            // Для обработки нажатых клавиш в Map3DView
#include <QSplitter>       // Для разделения Map3DView и панели управления
#include <QTabWidget>      // Для вкладок на панели управления
#include <QListWidget>     // Для списка вейпоинтов
#include <QTextEdit>       // Для отображения связей
#include <QFileDialog>     // Для диалогов открытия/сохранения
#include <QMouseEvent>     // Для обработки событий мыши, если потребуется
#include <QKeyEvent>       // Для обработки событий клавиатуры, если потребуется
#include <QMessageBox>     // Для сообщений пользователю
#include <QInputDialog>    // Для запроса пути к игре
#include <QSettings>       // Для сохранения и загрузки пути к игре
#include <QLabel>          // Добавлено для QLabel
#include <QStatusBar>      // Добавлено для QStatusBar
#include <QFutureWatcher>  // Добавлено для QFutureWatcher

#include "core/MapData/MapData.h"
#include "core/LoS/LineOfSight.h"
#include "core/Pathfinding/AStar.h"
#include "core/Pathfinding/BugPathfinder.h"

#ifdef Q_OS_WIN
#include <windows.h>  // Для глобальных хоткеев
#endif

#include "Map3DView/Map3DView.h"
#include "ProcessSelectionDialog/ProcessSelectionDialog.h"
#include "../core/Player/PlayerDataSource.h"
#include "core/WoWFileParser/MpqManager.h"

// Подключаем заголовочные файлы для выбора процесса и работы с памятью
#include "ProcessManager/ProcessManager.h"
#include "MemoryManager/MemoryManager.h"
// #include "Bot/Character/Character.h" // Убираем старый инклюд

// struct Obstacle;  // <--- Добавлено предварительное объявление

// УДАЛЕНО пространство имен Ui и объявление Ui::MainWindow

class MapDataManager;    // Forward declaration
class MpqManagerWidget;  // <--- ДОБАВЛЕНО ПРЕДВАРИТЕЛЬНОЕ ОБЪЯВЛЕНИЕ
// class MapData;         // Forward declaration - теперь не нужно, так как включаем полный заголовок

class MainWindow : public QMainWindow
{
    Q_OBJECT

   public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

   protected:  // Перемещаем nativeEvent в protected, как принято для обработчиков событий
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;
    void showEvent(QShowEvent *event) override;
    void closeEvent(QCloseEvent *event) override;

   private slots:
    void onConnectToProcessActionTriggered();  // Переименованный слот
    void onFocusOnPlayerButtonClicked();
    void onPlayerPositionChanged(const QVector3D &position);
    void requestPlayerPositionUpdate();
    void onOpenMapActionTriggered();                                     // Слот для действия "Открыть"
    void onSaveMapActionTriggered();                                     // Слот для действия "Сохранить"
    void onSaveMapAsActionTriggered();                                   // Слот для действия "Сохранить как"
    void onToggleRecordRouteActionTriggered();                           // Новый слот для записи маршрута
    void onRecordRouteTimerTimeout();                                    // Новый слот для таймера записи
    void onMap3DViewWaypointsChanged(const QList<Waypoint> &waypoints);  // Слот для обновления вейпоинтов из Map3DView
    void onSavePlayerPositionActionTriggered();                          // Слот для сохранения текущей точки игрока
    void onAddObstaclePointActionTriggered();                            // <--- НОВЫЙ СЛОТ для F2
    void onRunPathfindingTestActionTriggered();                          // Новый слот для теста поиска пути
    void onRunObstacleScenarioTestTriggered();                           // Новый слот для теста с препятствиями
    void onNewMap();
    void onClearWaypointsTriggered();

    // Слоты для BugPathfinder теста
    void onSetBugTestStart();
    void onSetBugTestGoal();
    void onRunBugTest();
    void onResetBugTest();
    void onBugTestTimerTimeout();
    void onBugPathFound(const QList<QVector3D> &path);
    void onBugPathNotFound();
    void onBugStateChanged(Core::Pathfinding::BugPathState newState);
    void onMapClickedForBugTest(const QVector3D &position, Qt::MouseButton button);

    void handleMpqInitializationFinished(MpqManager *initializedManager, const QString &triedPath);
    void initializeMapDataManager();
    void promptForGamePathAndInitialize(bool isFirstAttempt = false);
    void on_actionSelectWoWPath_triggered();

   private:
    // Вспомогательные методы для теста поиска пути
    // double heuristic(const Waypoint &a, const Waypoint &b); // <--- УДАЛЕНО
    // QList<int> aStarSearch(const MapData &mapData, int startId, int goalId); // <--- УДАЛЕНО

    void setupUi();        // Этот метод будет создавать UI в коде
    void createActions();  // Для создания QAction
    void createMenus();    // Для создания QMenu

    // Компоненты UI, создаваемые в setupUi()
    Map3DView *m_map3DView = nullptr;
    QTabWidget *m_rightTabWidget = nullptr;

    // Для вкладки "Вейпоинты"
    QListWidget *m_waypointsListWidget = nullptr;
    QLineEdit *m_waypointIdLineEdit = nullptr;
    QLineEdit *m_waypointNameLineEdit = nullptr;
    QLineEdit *m_waypointXLineEdit = nullptr;
    QLineEdit *m_waypointYLineEdit = nullptr;
    QLineEdit *m_waypointZLineEdit = nullptr;
    QTextEdit *m_connectionsTextEdit = nullptr;
    Waypoint *m_currentlySelectedWaypoint = nullptr;

    // Для вкладки "Игрок"
    QLabel *m_playerPositionLabel = nullptr;
    QPushButton *m_focusOnPlayerButton = nullptr;
    QPushButton *m_savePlayerPositionButton = nullptr;
    QPushButton *m_addObstaclePointButton = nullptr;
    QPushButton *m_toggleRecordRouteButton = nullptr;
    QLabel *m_recordedRouteStatusLabel = nullptr;

    // Для вкладки "A* Тест"
    QLineEdit *m_pathTestStartIdEdit = nullptr;
    QLineEdit *m_pathTestGoalIdEdit = nullptr;
    QPushButton *m_runPathTestButton = nullptr;
    QLabel *m_pathTestResultLabel = nullptr;

    // Для вкладки "Bug Тест"
    QPushButton *m_setBugStartButton = nullptr;
    QLabel *m_bugStartPosLabel = nullptr;
    QPushButton *m_setBugGoalButton = nullptr;
    QLabel *m_bugGoalPosLabel = nullptr;
    QPushButton *m_runBugTestButton = nullptr;
    QPushButton *m_resetBugTestButton = nullptr;
    QLabel *m_bugTestStatusLabel = nullptr;
    QLabel *m_bugTestPathLabel = nullptr;

    // Общие данные и менеджеры
    MapDataManager *m_mapDataManager = nullptr;
    MapData *m_currentMapData = nullptr;
    QString m_currentMapFilePath;

    MapEditor::PlayerCore::PlayerDataSource *m_playerDataSource = nullptr;
    MemoryManager *m_memoryManager = nullptr;
    QTimer *m_updateTimer = nullptr;

    // Действия меню
    QAction *m_newMapAction = nullptr;

    // Меню и действия
    QMenu *m_fileMenu = nullptr;
    QMenu *m_toolsMenu = nullptr;
    QAction *m_openMapAction = nullptr;
    QAction *m_saveMapAction = nullptr;
    QAction *m_saveMapAsAction = nullptr;
    QAction *m_connectToProcessAction = nullptr;
    QAction *m_exitAction = nullptr;
    QAction *m_toggleRecordRouteAction = nullptr;        // Новое действие
    QAction *m_savePlayerPositionAction = nullptr;       // Действие для сохранения точки игрока
    QAction *m_addObstaclePointAction = nullptr;         // <--- НОВОЕ ДЕЙСТВИЕ для F2
    QAction *m_runPathfindingTestAction = nullptr;       // Новое действие для теста поиска пути
    QAction *m_runObstacleTestScenarioAction = nullptr;  // Новое действие для теста с препятствиями
    QAction *m_selectWoWPathAction = nullptr;

    // Новые действия для BugPathfinder теста
    QAction *m_setBugTestStartAction = nullptr;
    QAction *m_setBugTestGoalAction = nullptr;
    QAction *m_runBugTestAction = nullptr;
    QAction *m_resetBugTestAction = nullptr;

    // Остальные необходимые компоненты
    QMetaObject::Connection m_playerPositionConnection;
    QTimer *m_positionUpdateTimer = nullptr;

    // Для записи маршрута
    bool m_isRecordingRoute = false;
    QTimer *m_recordRouteTimer = nullptr;
    QVector3D m_lastRecordedPosition;              // Для проверки дистанции
    int m_lastRecordedWaypointId = 0;              // Для соединения точек
    bool m_isFirstPointInRecordingSession = true;  // Флаг для первой точки в сессии

    // Члены для BugPathfinder теста
    Core::Pathfinding::BugPathfinder m_bugPathfinder;
    QTimer m_bugTestTimer;
    QList<QVector3D> m_bugPathCalculatedPath;
    QVector3D m_bugTestStartPoint;
    QVector3D m_bugTestGoalPoint;
    bool m_selectingBugTestStartPoint = false;
    bool m_selectingBugTestGoalPoint = false;

    MpqManager *m_mpqManager = nullptr;              // <--- ИСПРАВЛЕНО (и #include добавлен выше)
    MpqManagerWidget *m_mpqManagerWidget = nullptr;  // <--- Новое поле
    QString m_gamePath;                              // <--- Новое поле

    // Для теста Bug Pathfinder
    QVector3D m_bugTestStartPos;

    QList<QVector3D> m_recordedRoutePoints;

    void setupConnections();
    void updateUIBasedOnConnection(bool isConnected);
    void loadMap(const QString &filePath);
    bool saveMap(const QString &filePath);  // Вспомогательная функция для сохранения, возвращает bool

#ifdef Q_OS_WIN
    // Идентификатор для глобального хоткея F1
    static const int GLOBAL_HOTKEY_ID_F1 = 1;
    static const int GLOBAL_HOTKEY_ID_F2 = 2;  // <--- НОВЫЙ ID для F2
#endif

    // TODO: Добавить QMenuBar, QToolBar, QStatusBar и т.д.
    // QMenuBar уже будет создан напрямую

    // Методы для обновления UI (если они нужны)
    void updateWaypointList();
    void updateConnectionsTextEdit();
    void updateWindowTitle();

    void setMapModified(bool modified);
    void initializeMpqManager();

    QStatusBar *m_statusBar = nullptr;
    QFutureWatcher<QPair<MpqManager *, QString>> *m_mpqWatcher = nullptr;
};