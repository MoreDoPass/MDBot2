#include "MainWindow.h"
#include "Map3DView/Map3DView.h"
#include "gui/MpqManager/MpqManagerWidget.h"  // <--- ДОБАВЛЕНО
#include <QMessageBox>
#include <QDir>
#include <QStandardPaths>
#include <QLoggingCategory>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QPushButton>
#include <QSpacerItem>
#include <QFileDialog>
#include <QWidget>
#include <QTimer>
#include <QMenuBar>
#include <QKeySequence>
#include <QStatusBar>
#include <QElapsedTimer>
#include <cmath>
#include <vector>
#include <queue>
#include <limits>
#include <set>
#include <map>
#include <QRandomGenerator>
#include <QHash>
#include <algorithm>
#include <QDockWidget>   // Для док-виджетов, если они понадобятся
#include <QInputDialog>  // Для запроса строки у пользователя
#include <QSettings>     // Для сохранения настроек, например, пути к игре
#include <QtConcurrent/QtConcurrent>
#include <QFutureWatcher>

// Для ProcessManager
#include "ProcessManager/ProcessManager.h"
// Для MemoryManager
#include "MemoryManager/MemoryManager.h"
// Для MapDataManager и MapData
#include "core/MapData/MapDataManager.h"
#include "core/MapData/MapData.h"
#include "core/LoS/LineOfSight.h"    // <--- Убедимся, что включен
#include "core/Pathfinding/AStar.h"  // <--- Убедимся, что включен

// Объявление категории логирования
Q_LOGGING_CATEGORY(mainWindowLog, "gui.mainWindow")

// Определим константы для записи маршрута где-нибудь в начале файла или в .h, если они нужны в других местах
const int RECORD_TIMER_INTERVAL_MS = 1000;             // Интервал таймера записи в мс (1 секунда)
const float MIN_DISTANCE_BETWEEN_WAYPOINTS_SQ = 4.0f;  // Квадрат минимального расстояния (2 метра) для оптимизации

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_map3DView(new Map3DView(this)),
      m_mapDataManager(new MapDataManager()),
      m_playerDataSource(nullptr),           // Инициализируем позже
      m_memoryManager(new MemoryManager()),  // Предполагаем, что конструктор по умолчанию
      m_updateTimer(new QTimer(this)),
      m_currentMapData(new MapData()),  // <--- ИНИЦИАЛИЗИРОВАНО
      m_currentMapFilePath(""),
      m_recordRouteTimer(new QTimer(this)),
      m_bugPathfinder(this),  // Если конструктор по умолчанию или ожидает this, компилятор подскажет
      m_bugTestTimer(),       // QTimer унаследует родителя от MainWindow
      m_mpqManager(nullptr),
      m_mpqManagerWidget(nullptr),
      m_positionUpdateTimer(new QTimer(this)),  // <--- ИНИЦИАЛИЗИРОВАНО (перенесено из .h как поле)
      m_mpqWatcher(
          new QFutureWatcher<QPair<MpqManager *, QString>>(this)),  // <-- Инициализируем здесь или в конструкторе
      m_statusBar(nullptr)                                          // Инициализируем nullptr, установим в setupUi
{
    qCInfo(mainWindowLog) << "MainWindow constructor started.";
    setWindowTitle("MapEditor - MDBot2");
    setMinimumSize(1024, 768);  // Устанавливаем минимальный размер окна

    // Инициализация PlayerDataSource с MemoryManager
    m_playerDataSource = new MapEditor::PlayerCore::PlayerDataSource(m_memoryManager, this);  // <--- ИСПРАВЛЕНО

    setupUi();  // Создаем UI элементы (включая m_rightTabWidget)
    createActions();
    createMenus();
    // createToolBars(); // Если будут панели инструментов
    // createStatusBar(); // Если будет строка состояния

    setupConnections();  // Настраиваем сигналы и слоты

    // Начальное состояние UI в зависимости от подключения к процессу
    updateUIBasedOnConnection(false);
    updateWaypointList();  // Обновляем список вейпоинтов (изначально пустой)
    updateWindowTitle();   // Устанавливаем заголовок окна

    // Подключаем watcher к слоту ПЕРЕД первым вызовом initializeMpqManager
    connect(m_mpqWatcher, &QFutureWatcher<QPair<MpqManager *, QString>>::finished, this,
            [this]()
            {
                QPair<MpqManager *, QString> result = m_mpqWatcher->result();
                handleMpqInitializationFinished(result.first, result.second);
            });

    initializeMpqManager();  // <-- Вызов здесь

    qCInfo(mainWindowLog) << "MainWindow constructed successfully.";
}

MainWindow::~MainWindow()
{
    qCInfo(mainWindowLog) << "MainWindow destructor started.";
    // Таймеры остановятся автоматически при удалении родителя (MainWindow)
    // m_map3DView, m_mapDataManager, m_playerDataSource, m_memoryManager, m_processManager
    // m_updateTimer, m_recordRouteTimer, m_bugPathfinder, m_bugTestTimer
    // будут удалены автоматически Qt, так как MainWindow их родитель

    // Явно удаляем m_mpqManager, так как мы создали его через new
    if (m_mpqManager)
    {
        delete m_mpqManager;
        m_mpqManager = nullptr;
    }
    // m_mpqManagerWidget будет удален Qt, если он был добавлен в layout/tabwidget с MainWindow как родитель

    qCInfo(mainWindowLog) << "MainWindow destructed successfully.";
}

void MainWindow::createActions()
{
    m_openMapAction = new QAction(tr("&Открыть карту..."), this);
    m_openMapAction->setShortcuts(QKeySequence::Open);
    m_openMapAction->setStatusTip(tr("Открыть существующий файл карты"));

    m_saveMapAction = new QAction(tr("&Сохранить карту"), this);
    m_saveMapAction->setShortcuts(QKeySequence::Save);
    m_saveMapAction->setStatusTip(tr("Сохранить текущую карту"));
    m_saveMapAction->setEnabled(false);

    m_saveMapAsAction = new QAction(tr("Сохранить карту &как..."), this);
    m_saveMapAsAction->setShortcuts(QKeySequence::SaveAs);
    m_saveMapAsAction->setStatusTip(tr("Сохранить текущую карту в новый файл"));
    m_saveMapAsAction->setEnabled(false);

    m_exitAction = new QAction(tr("&Выход"), this);
    m_exitAction->setShortcuts(QKeySequence::Quit);
    m_exitAction->setStatusTip(tr("Выйти из приложения"));

    m_connectToProcessAction = new QAction(tr("&Подключиться к процессу..."), this);
    m_connectToProcessAction->setStatusTip(tr("Подключиться к игровому процессу WoW"));

    m_toggleRecordRouteAction = new QAction(tr("&Начать запись маршрута"), this);
    m_toggleRecordRouteAction->setCheckable(true);  // Делаем действие переключаемым
    m_toggleRecordRouteAction->setStatusTip(tr("Начать или остановить запись маршрута по движению игрока"));
    m_toggleRecordRouteAction->setEnabled(false);  // Будет активно только при подключении к процессу

    m_savePlayerPositionAction = new QAction(tr("Сохранить &точку персонажа"), this);
    m_savePlayerPositionAction->setShortcut(Qt::Key_F1);  // Пока локальный хоткей F1
    m_savePlayerPositionAction->setStatusTip(tr("Сохранить текущее местоположение игрока как новую путевую точку"));
    m_savePlayerPositionAction->setEnabled(false);  // Будет активно только при подключении к процессу

    m_runPathfindingTestAction = new QAction(tr("&Запустить тест поиска пути (случайный)"), this);
    m_runPathfindingTestAction->setStatusTip(
        tr("Создает большую сетку случайных точек и тестирует A* между двумя из них"));

    m_runObstacleTestScenarioAction = new QAction(tr("Запустить тест с &препятствиями (Заборчик)"), this);
    m_runObstacleTestScenarioAction->setStatusTip(tr("Создает тестовый сценарий с путевыми точками и препятствиями"));

    m_selectWoWPathAction = new QAction(tr("Указать путь к &WoW..."), this);  // <-- Создание действия
    m_selectWoWPathAction->setStatusTip(tr("Указать корневую директорию игры World of Warcraft для загрузки MPQ"));

    m_addObstaclePointAction = new QAction(tr("Добавить &точку препятствия (F2)"), this);  // <--- НОВОЕ ДЕЙСТВИЕ
    m_addObstaclePointAction->setShortcut(Qt::Key_F2);                                     // Локальный хоткей F2
    m_addObstaclePointAction->setStatusTip(
        tr("Добавить точку для текущего создаваемого препятствия по координатам игрока"));
    m_addObstaclePointAction->setEnabled(false);  // Будет активно только при подключении к процессу

    // Действия для BugPathfinder теста
    m_setBugTestStartAction = new QAction(tr("Set Bug Test Start Point"), this);
    m_setBugTestStartAction->setStatusTip(tr("Select the starting point for the Bug Pathfinder test on the map"));
    connect(m_setBugTestStartAction, &QAction::triggered, this, &MainWindow::onSetBugTestStart);

    m_setBugTestGoalAction = new QAction(tr("Set Bug Test Goal Point"), this);
    m_setBugTestGoalAction->setStatusTip(tr("Select the goal point for the Bug Pathfinder test on the map"));
    connect(m_setBugTestGoalAction, &QAction::triggered, this, &MainWindow::onSetBugTestGoal);

    m_runBugTestAction = new QAction(tr("Run Bug Pathfinder Test"), this);
    m_runBugTestAction->setStatusTip(tr("Run the Bug Pathfinder test with selected start and goal points"));
    m_runBugTestAction->setEnabled(false);  // Будет активна, когда выбраны старт и цель
    connect(m_runBugTestAction, &QAction::triggered, this, &MainWindow::onRunBugTest);

    m_resetBugTestAction = new QAction(tr("Reset Bug Pathfinder Test"), this);
    m_resetBugTestAction->setStatusTip(tr("Reset the Bug Pathfinder test state and clear points"));
    connect(m_resetBugTestAction, &QAction::triggered, this, &MainWindow::onResetBugTest);
}

void MainWindow::createMenus()
{
    m_fileMenu = menuBar()->addMenu(tr("&Файл"));
    m_fileMenu->addAction(m_openMapAction);
    m_fileMenu->addAction(m_saveMapAction);
    m_fileMenu->addAction(m_saveMapAsAction);
    m_fileMenu->addSeparator();
    m_fileMenu->addAction(m_selectWoWPathAction);  // <-- Добавление в меню Файл
    m_fileMenu->addSeparator();
    m_fileMenu->addAction(m_exitAction);

    m_toolsMenu = menuBar()->addMenu(tr("&Инструменты"));
    m_toolsMenu->addAction(m_connectToProcessAction);
    m_toolsMenu->addAction(m_toggleRecordRouteAction);   // Добавляем действие в меню
    m_toolsMenu->addAction(m_savePlayerPositionAction);  // Добавляем новое действие в меню
    m_toolsMenu->addAction(m_addObstaclePointAction);    // <--- ДОБАВЛЯЕМ ДЕЙСТВИЕ F2 В МЕНЮ
    m_toolsMenu->addSeparator();                         // Отделим тестовое действие
    m_toolsMenu->addAction(m_runPathfindingTestAction);
    m_toolsMenu->addAction(m_runObstacleTestScenarioAction);

    // Добавляем подменю для Bug Pathfinder
    QMenu *bugTestMenu = m_toolsMenu->addMenu(tr("Bug Pathfinder Test"));
    bugTestMenu->addAction(m_setBugTestStartAction);
    bugTestMenu->addAction(m_setBugTestGoalAction);
    bugTestMenu->addAction(m_runBugTestAction);
    bugTestMenu->addAction(m_resetBugTestAction);
}

void MainWindow::setupUi()
{
    qCInfo(mainWindowLog) << "Setting up UI...";
    m_statusBar = statusBar();  // <-- Инициализация m_statusBar
    if (m_statusBar) m_statusBar->showMessage("MapEditor UI Setup...", 2000);

    // Центральный виджет и главный layout
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QHBoxLayout *mainLayout = new QHBoxLayout(centralWidget);  // Главный горизонтальный layout

    // QSplitter для разделения 3D вида и правой панели
    QSplitter *splitter = new QSplitter(Qt::Horizontal, this);
    splitter->addWidget(m_map3DView);  // Map3DView слева

    // --- Правая панель управления (с вкладками) ---
    m_rightTabWidget = new QTabWidget(this);  // Создаем QTabWidget
    m_rightTabWidget->setMinimumWidth(300);   // Минимальная ширина для панели

    // Вкладка 1: Вейпоинты
    QWidget *waypointsTab = new QWidget(this);
    QVBoxLayout *waypointsLayout = new QVBoxLayout(waypointsTab);

    m_waypointsListWidget = new QListWidget(this);
    waypointsLayout->addWidget(new QLabel("Вейпоинты:", this));
    waypointsLayout->addWidget(m_waypointsListWidget);

    m_waypointIdLineEdit = new QLineEdit(this);
    m_waypointIdLineEdit->setPlaceholderText("ID");
    m_waypointIdLineEdit->setReadOnly(true);  // ID только для чтения
    waypointsLayout->addWidget(m_waypointIdLineEdit);

    m_waypointNameLineEdit = new QLineEdit(this);
    m_waypointNameLineEdit->setPlaceholderText("Имя");
    waypointsLayout->addWidget(m_waypointNameLineEdit);

    m_waypointXLineEdit = new QLineEdit(this);
    m_waypointXLineEdit->setPlaceholderText("X");
    m_waypointYLineEdit = new QLineEdit(this);
    m_waypointYLineEdit->setPlaceholderText("Y");
    m_waypointZLineEdit = new QLineEdit(this);
    m_waypointZLineEdit->setPlaceholderText("Z");
    QHBoxLayout *coordsLayout = new QHBoxLayout();
    coordsLayout->addWidget(m_waypointXLineEdit);
    coordsLayout->addWidget(m_waypointYLineEdit);
    coordsLayout->addWidget(m_waypointZLineEdit);
    waypointsLayout->addLayout(coordsLayout);

    m_connectionsTextEdit = new QTextEdit(this);
    m_connectionsTextEdit->setPlaceholderText("Связанные ID (через запятую)");
    waypointsLayout->addWidget(m_connectionsTextEdit);

    QPushButton *saveWaypointButton = new QPushButton("Сохранить изменения вейпоинта", this);
    waypointsLayout->addWidget(saveWaypointButton);

    QPushButton *removeWaypointButton = new QPushButton("Удалить выбранный вейпоинт", this);
    waypointsLayout->addWidget(removeWaypointButton);

    QPushButton *clearWaypointsButton = new QPushButton("Очистить все вейпоинты", this);
    waypointsLayout->addWidget(clearWaypointsButton);

    m_rightTabWidget->addTab(waypointsTab, "Вейпоинты");

    // Вкладка 2: Управление игроком и запись маршрута
    QWidget *playerTab = new QWidget(this);
    QVBoxLayout *playerLayout = new QVBoxLayout(playerTab);

    m_playerPositionLabel = new QLabel("Позиция игрока: (нет данных)", this);
    playerLayout->addWidget(m_playerPositionLabel);

    m_focusOnPlayerButton = new QPushButton("Фокус на игроке", this);
    playerLayout->addWidget(m_focusOnPlayerButton);

    m_savePlayerPositionButton = new QPushButton("Сохранить позицию игрока как вейпоинт (F1)", this);
    playerLayout->addWidget(m_savePlayerPositionButton);

    m_addObstaclePointButton = new QPushButton("Добавить точку препятствия на позиции игрока (F2)", this);
    playerLayout->addWidget(m_addObstaclePointButton);

    m_toggleRecordRouteButton = new QPushButton("Начать запись маршрута", this);
    playerLayout->addWidget(m_toggleRecordRouteButton);
    m_recordedRouteStatusLabel = new QLabel("Запись маршрута: неактивна", this);
    playerLayout->addWidget(m_recordedRouteStatusLabel);

    playerLayout->addStretch();  // Добавляем растягивающийся элемент, чтобы кнопки были сверху
    m_rightTabWidget->addTab(playerTab, "Игрок");

    // Вкладка 3: Тестирование A*
    QWidget *pathfindingTestTab = new QWidget(this);
    QVBoxLayout *pathfindingTestLayout = new QVBoxLayout(pathfindingTestTab);
    m_pathTestStartIdEdit = new QLineEdit(this);
    m_pathTestStartIdEdit->setPlaceholderText("Start WP ID");
    pathfindingTestLayout->addWidget(m_pathTestStartIdEdit);
    m_pathTestGoalIdEdit = new QLineEdit(this);
    m_pathTestGoalIdEdit->setPlaceholderText("Goal WP ID");
    pathfindingTestLayout->addWidget(m_pathTestGoalIdEdit);
    m_runPathTestButton = new QPushButton("Запустить тест A*", this);
    pathfindingTestLayout->addWidget(m_runPathTestButton);
    m_pathTestResultLabel = new QLabel("Результат: ", this);
    pathfindingTestLayout->addWidget(m_pathTestResultLabel);
    pathfindingTestLayout->addStretch();
    m_rightTabWidget->addTab(pathfindingTestTab, "A* Тест");

    // Вкладка 4: Тестирование Bug Pathfinder
    QWidget *bugTestTab = new QWidget(this);
    QVBoxLayout *bugTestLayout = new QVBoxLayout(bugTestTab);

    m_setBugStartButton = new QPushButton("Указать старт (ПКМ на карте)", this);
    bugTestLayout->addWidget(m_setBugStartButton);
    m_bugStartPosLabel = new QLabel("Старт: не указан", this);
    bugTestLayout->addWidget(m_bugStartPosLabel);

    m_setBugGoalButton = new QPushButton("Указать цель (ПКМ на карте)", this);
    bugTestLayout->addWidget(m_setBugGoalButton);
    m_bugGoalPosLabel = new QLabel("Цель: не указана", this);
    bugTestLayout->addWidget(m_bugGoalPosLabel);

    m_runBugTestButton = new QPushButton("Запустить Bug Тест", this);
    bugTestLayout->addWidget(m_runBugTestButton);
    m_resetBugTestButton = new QPushButton("Сбросить Bug Тест", this);
    bugTestLayout->addWidget(m_resetBugTestButton);

    m_bugTestStatusLabel = new QLabel("Статус: Бездействие", this);
    bugTestLayout->addWidget(m_bugTestStatusLabel);
    m_bugTestPathLabel = new QLabel("Путь: ", this);
    m_bugTestPathLabel->setWordWrap(true);
    bugTestLayout->addWidget(m_bugTestPathLabel);

    bugTestLayout->addStretch();
    m_rightTabWidget->addTab(bugTestTab, "Bug Тест");

    // Вкладка 5: MPQ Файлы
    m_mpqManagerWidget = new MpqManagerWidget(nullptr, this);  // Передаем nullptr, менеджер будет установлен позже
    m_rightTabWidget->addTab(m_mpqManagerWidget, "MPQ Файлы");

    splitter->addWidget(m_rightTabWidget);  // Добавляем правую панель в сплиттер
    // Устанавливаем начальные размеры для сплиттера (например, 70% для 3D вида, 30% для панели)
    splitter->setSizes({static_cast<int>(width() * 0.7), static_cast<int>(width() * 0.3)});

    mainLayout->addWidget(splitter);  // Добавляем сплиттер в главный layout
    centralWidget->setLayout(mainLayout);

    qCInfo(mainWindowLog) << "UI setup completed.";
}

void MainWindow::setupConnections()
{
    connect(m_openMapAction, &QAction::triggered, this, &MainWindow::onOpenMapActionTriggered);
    connect(m_saveMapAction, &QAction::triggered, this, &MainWindow::onSaveMapActionTriggered);
    connect(m_saveMapAsAction, &QAction::triggered, this, &MainWindow::onSaveMapAsActionTriggered);
    connect(m_exitAction, &QAction::triggered, this, &QWidget::close);

    connect(m_connectToProcessAction, &QAction::triggered, this, &MainWindow::onConnectToProcessActionTriggered);

    connect(m_toggleRecordRouteAction, &QAction::triggered, this, &MainWindow::onToggleRecordRouteActionTriggered);

    connect(m_focusOnPlayerButton, &QPushButton::clicked, this, &MainWindow::onFocusOnPlayerButtonClicked);

    // Соединяем сигнал изменения вейпоинтов из Map3DView со слотом в MainWindow
    if (m_map3DView)  // Добавим проверку на null, хотя он должен быть создан ранее
    {
        connect(m_map3DView, &Map3DView::waypointsChanged, this, &MainWindow::onMap3DViewWaypointsChanged);
    }

    connect(m_savePlayerPositionAction, &QAction::triggered, this, &MainWindow::onSavePlayerPositionActionTriggered);
    connect(m_addObstaclePointAction, &QAction::triggered, this,
            &MainWindow::onAddObstaclePointActionTriggered);  // <--- ПОДКЛЮЧАЕМ СИГНАЛ
    connect(m_runPathfindingTestAction, &QAction::triggered, this, &MainWindow::onRunPathfindingTestActionTriggered);
    connect(m_runObstacleTestScenarioAction, &QAction::triggered, this,
            &MainWindow::onRunObstacleScenarioTestTriggered);

    connect(m_selectWoWPathAction, &QAction::triggered, this,
            &MainWindow::on_actionSelectWoWPath_triggered);  // <-- Подключение сигнала

    // Соединения для BugPathfinder теста
    connect(&m_bugTestTimer, &QTimer::timeout, this, &MainWindow::onBugTestTimerTimeout);
    connect(&m_bugPathfinder, &Core::Pathfinding::BugPathfinder::pathFound, this, &MainWindow::onBugPathFound);
    connect(&m_bugPathfinder, &Core::Pathfinding::BugPathfinder::pathNotFound, this, &MainWindow::onBugPathNotFound);
    connect(&m_bugPathfinder, &Core::Pathfinding::BugPathfinder::stateChanged, this, &MainWindow::onBugStateChanged);
    connect(m_map3DView, &Map3DView::mapClicked, this, &MainWindow::onMapClickedForBugTest);
}

void MainWindow::onOpenMapActionTriggered()
{
    QString startDir = QDir::currentPath() + "/../../resources/maps";
    QString filePath =
        QFileDialog::getOpenFileName(this, tr("Открыть карту"), startDir, tr("MapData Files (*.json);;All Files (*)"));

    if (!filePath.isEmpty())
    {
        loadMap(filePath);
    }
    else
    {
        qCInfo(mainWindowLog) << "File selection cancelled.";
    }
}

void MainWindow::onSaveMapActionTriggered()
{
    if (m_currentMapFilePath.isEmpty())
    {
        onSaveMapAsActionTriggered();
    }
    else
    {
        if (saveMap(m_currentMapFilePath))
        {
            statusBar()->showMessage(tr("Карта сохранена: %1").arg(m_currentMapFilePath), 2000);
        }
    }
}

void MainWindow::onSaveMapAsActionTriggered()
{
    QString startDir = m_currentMapFilePath.isEmpty() ? (QDir::currentPath() + "/../../resources/maps")
                                                      : QFileInfo(m_currentMapFilePath).absolutePath();

    QString filePath = QFileDialog::getSaveFileName(this, tr("Сохранить карту как..."), startDir,
                                                    tr("MapData Files (*.json);;All Files (*)"));

    if (!filePath.isEmpty())
    {
        if (!filePath.endsWith(".json", Qt::CaseInsensitive))
        {
            filePath += ".json";
        }
        if (saveMap(filePath))
        {
            m_currentMapFilePath = filePath;
            setWindowTitle(tr("Map Editor - %1").arg(QFileInfo(filePath).fileName()));
            statusBar()->showMessage(tr("Карта сохранена как: %1").arg(filePath), 2000);
            if (m_saveMapAction) m_saveMapAction->setEnabled(true);
        }
    }
    else
    {
        qCInfo(mainWindowLog) << "Save As file selection cancelled.";
    }
}

void MainWindow::onConnectToProcessActionTriggered()
{
    qCInfo(mainWindowLog) << "Connect to process action triggered.";

    // Получаем список процессов Wow.exe
    // std::vector<ProcessInfo> processes = m_processManager->findProcessesByName(L"Wow.exe"); // <--- ИЗМЕНЕНО
    std::vector<ProcessInfo> processes = ProcessManager::findProcessesByName(L"Wow.exe");

    if (processes.empty())
    {
        QMessageBox::information(this, tr("Выбор процесса"), tr("Процессы 'Wow.exe' не найдены."));
        qCInfo(mainWindowLog) << "No 'Wow.exe' processes found.";
        return;
    }

    ProcessSelectionDialog dialog(processes, this);
    if (dialog.exec() == QDialog::Accepted && dialog.isProcessSelected())
    {
        ProcessInfo selectedProcess = dialog.getSelectedProcess();
        if (selectedProcess.pid != 0)
        {
            qCInfo(mainWindowLog) << "Process selected: " << QString::fromStdWString(selectedProcess.name)
                                  << " (PID:" << selectedProcess.pid << ")";
            if (!m_memoryManager->openProcess(selectedProcess.pid))
            {
                qCWarning(mainWindowLog) << "MemoryManager failed to open process PID: " << selectedProcess.pid;
                QMessageBox::critical(this, tr("Ошибка"),
                                      tr("MemoryManager не удалось открыть процесс. Запущен ли он с нужными правами?"));
                updateUIBasedOnConnection(false);
                return;
            }
            qCInfo(mainWindowLog) << "MemoryManager successfully opened process PID: " << selectedProcess.pid;
            if (m_playerDataSource->setActiveProcess(selectedProcess.pid))
            {
                qCInfo(mainWindowLog) << "Successfully attached to process PID: " << selectedProcess.pid;
                updateUIBasedOnConnection(true);
                if (m_playerPositionConnection) QObject::disconnect(m_playerPositionConnection);
                m_playerPositionConnection =
                    connect(m_playerDataSource, &MapEditor::PlayerCore::PlayerDataSource::positionUpdated, this,
                            &MainWindow::onPlayerPositionChanged);
                m_playerDataSource->updatePosition();
                m_positionUpdateTimer->start(200);
            }
            else
            {
                qCWarning(mainWindowLog) << "PlayerDataSource failed to attach to process PID: " << selectedProcess.pid;
                QMessageBox::critical(this, tr("Ошибка"),
                                      tr("PlayerDataSource не удалось подключиться к процессу. Убедитесь, что это "
                                         "32-битный процесс WoW 3.3.5a и попробуйте снова."));
                updateUIBasedOnConnection(false);
                m_memoryManager->closeProcess();
            }
        }
        else
        {
            qCInfo(mainWindowLog) << "No process selected from dialog (PID is 0).";
            updateUIBasedOnConnection(false);
        }
    }
    else
    {
        qCInfo(mainWindowLog) << "Process selection cancelled or no process chosen.";
        updateUIBasedOnConnection(false);
    }
}

void MainWindow::loadMap(const QString &filePath)
{
    qCDebug(mainWindowLog) << "Attempting to load map from:" << filePath;
    MapData newMapData;  // Временный объект для загрузки
    // Используем MapDataManager для загрузки
    if (m_mapDataManager && m_mapDataManager->loadMapData(filePath, newMapData))
    {
        m_map3DView->clearMapDisplayData();
        *m_currentMapData = newMapData;   // Копируем загруженные данные в текущие
        m_currentMapFilePath = filePath;  // Используем объявленный член класса
        setWindowTitle(QString("MapEditor - %1").arg(QFileInfo(filePath).fileName()));

        m_map3DView->setWaypoints(m_currentMapData->waypoints);
        m_map3DView->setObstacles(m_currentMapData->obstacles);

        updateWaypointList();         // Предполагаем, что этот метод существует
        updateConnectionsTextEdit();  // Предполагаем, что этот метод существует

        if (m_saveMapAction) m_saveMapAction->setEnabled(true);
        if (m_saveMapAsAction) m_saveMapAsAction->setEnabled(true);
        statusBar()->showMessage(tr("Карта загружена: %1").arg(filePath), 2000);
    }
    else
    {
        qCWarning(mainWindowLog) << "Failed to load map data from" << filePath << "using MapDataManager.";
        QMessageBox::warning(this, tr("Загрузка данных карты"),
                             tr("Не удалось загрузить данные карты из файла: %1").arg(filePath));
        // Можно очистить вид, если загрузка не удалась, или оставить как есть
        // m_map3DView->clearMapDisplayData();
        // m_currentMapData->clear();
        // m_currentMapFilePath.clear();
        // setWindowTitle(tr("Map Editor - MDBot2"));
        statusBar()->showMessage(tr("Ошибка загрузки карты"), 2000);
    }
}

bool MainWindow::saveMap(const QString &filePath)
{
    if (!m_mapDataManager || !m_currentMapData)
    {
        qCWarning(mainWindowLog) << "MapDataManager or MapData is null. Cannot save map.";
        QMessageBox::critical(this, tr("Ошибка сохранения"), tr("Невозможно сохранить карту: отсутствуют данные."));
        return false;
    }

    if (m_mapDataManager->saveMapData(filePath, *m_currentMapData))
    {
        qCInfo(mainWindowLog) << "Map data successfully saved to:" << filePath;
        return true;
    }
    else
    {
        qCWarning(mainWindowLog) << "Failed to save map data to:" << filePath;
        QMessageBox::critical(this, tr("Ошибка сохранения"),
                              tr("Не удалось сохранить данные карты в файл: %1").arg(filePath));
        return false;
    }
}

void MainWindow::onPlayerPositionChanged(const QVector3D &position)
{
    if (m_map3DView)
    {
        m_map3DView->updatePlayerPosition(position);
    }
}

void MainWindow::requestPlayerPositionUpdate()
{
    if (m_playerDataSource && m_playerDataSource->isHookSet())
    {
        m_playerDataSource->updatePosition();
    }
}

void MainWindow::onToggleRecordRouteActionTriggered()
{
    if (!m_playerDataSource || !m_playerDataSource->isHookSet())
    {
        QMessageBox::warning(this, tr("Запись маршрута"), tr("Необходимо подключиться к процессу игры."));
        m_toggleRecordRouteAction->setChecked(false);  // Сбрасываем состояние кнопки
        m_isRecordingRoute = false;
        return;
    }

    if (!m_currentMapData || m_currentMapFilePath.isEmpty())
    {
        QMessageBox::warning(this, tr("Запись маршрута"), tr("Сначала откройте или сохраните карту."));
        m_toggleRecordRouteAction->setChecked(false);
        m_isRecordingRoute = false;
        return;
    }

    m_isRecordingRoute = m_toggleRecordRouteAction->isChecked();

    if (m_isRecordingRoute)
    {
        m_toggleRecordRouteAction->setText(tr("&Остановить запись маршрута"));
        m_toggleRecordRouteAction->setStatusTip(tr("Остановить запись маршрута"));
        qCInfo(mainWindowLog) << "Route recording started.";

        m_isFirstPointInRecordingSession = true;  // Сбрасываем флаг для новой сессии
        m_lastRecordedWaypointId = 0;             // Сбрасываем ID последней точки
        // Можно сразу записать первую точку или подождать таймера/смещения
        // Для простоты, первая точка запишется при первом срабатывании таймера, если игрок сместился
        m_lastRecordedPosition = m_playerDataSource->currentPosition();  // Запоминаем начальную позицию для сравнения

        m_recordRouteTimer->start(RECORD_TIMER_INTERVAL_MS);
        statusBar()->showMessage(tr("Запись маршрута начата..."), 3000);
    }
    else
    {
        m_recordRouteTimer->stop();
        m_toggleRecordRouteAction->setText(tr("&Начать запись маршрута"));
        m_toggleRecordRouteAction->setStatusTip(tr("Начать запись маршрута по движению игрока"));
        qCInfo(mainWindowLog) << "Route recording stopped.";
        statusBar()->showMessage(tr("Запись маршрута остановлена."), 3000);
    }
}

void MainWindow::onRecordRouteTimerTimeout()
{
    if (!m_isRecordingRoute || !m_playerDataSource || !m_playerDataSource->isHookSet() || !m_currentMapData)
    {
        m_recordRouteTimer->stop();
        m_isRecordingRoute = false;
        if (m_toggleRecordRouteAction)
        {
            m_toggleRecordRouteAction->setChecked(false);
            m_toggleRecordRouteAction->setText(tr("&Начать запись маршрута"));
            m_toggleRecordRouteAction->setStatusTip(tr("Начать запись маршрута по движению игрока"));
        }
        qCWarning(mainWindowLog) << "Route recording stopped due to invalid state in timer.";
        return;
    }

    QVector3D currentPlayerPos = m_playerDataSource->currentPosition();
    if (currentPlayerPos.isNull())
    {
        qCWarning(mainWindowLog) << "Cannot record waypoint: current player position is null.";
        return;
    }

    // Пока что просто добавляем точку при каждом тике таймера, если позиция изменилась с прошлой
    // (или это первая точка). Проверку на минимальное расстояние добавим позже.
    // Для QVector3D сравнение на точное равенство может быть не всегда надежным из-за float погрешностей,
    // но для начала сойдет, если игрок реально двигается.
    // Более строгая проверка будет m_lastRecordedPosition.distanceToPoint(currentPlayerPos) > НЕКОТОРЫЙ_МАЛЫЙ_ЭПСИЛОН

    // Простая проверка, чтобы не создавать точки на одном месте, если игрок стоит
    // Используем сохраненную m_lastRecordedPosition из onToggleRecordRouteActionTriggered или предыдущего тика
    // (но m_lastRecordedPosition еще не обновляется в этом слоте)
    // Исправим: m_lastRecordedPosition должна обновляться здесь, а не в onToggleRecordRouteActionTriggered после
    // первого раза

    // Генерируем простой ID. В будущем сделаем надежнее.
    int newWaypointId = 1;
    if (!m_currentMapData->waypoints.isEmpty())
    {
        for (const auto &wp : m_currentMapData->waypoints)
        {
            if (wp.id >= newWaypointId)
            {
                newWaypointId = wp.id + 1;
            }
        }
    }
    // Если это первая точка в сессии, или игрок сдвинулся
    // Пока для простоты будем добавлять всегда, когда таймер тикает и позиция не null.
    // Проверку на m_lastRecordedPosition и MIN_DISTANCE_BETWEEN_WAYPOINTS_SQ добавим на следующем шаге.

    Waypoint newWaypoint;
    newWaypoint.id = newWaypointId;
    newWaypoint.name = QString("Recorded_WP_%1").arg(newWaypointId);
    newWaypoint.coordinates = currentPlayerPos;
    // newWaypoint.connections - теперь будем заполнять

    if (!m_isFirstPointInRecordingSession && m_lastRecordedWaypointId != 0)
    {
        Waypoint *prevWaypoint = m_currentMapData->findWaypointById(m_lastRecordedWaypointId);
        if (prevWaypoint)
        {
            prevWaypoint->connectedWaypointIds.insert(newWaypoint.id);
            newWaypoint.connectedWaypointIds.insert(m_lastRecordedWaypointId);
            qCDebug(mainWindowLog) << "Connected new WP ID:" << newWaypoint.id
                                   << "with previous WP ID:" << m_lastRecordedWaypointId;
        }
        else
        {
            qCWarning(mainWindowLog) << "Could not find previous waypoint with ID:" << m_lastRecordedWaypointId
                                     << "to connect with new WP ID:" << newWaypoint.id;
        }
    }

    m_currentMapData->addWaypoint(newWaypoint);
    qCDebug(mainWindowLog) << "Recorded waypoint:" << newWaypoint.id << "at" << newWaypoint.coordinates
                           << "Connections:" << newWaypoint.connectedWaypointIds;

    m_isFirstPointInRecordingSession = false;
    m_lastRecordedWaypointId = newWaypoint.id;
    m_lastRecordedPosition =
        currentPlayerPos;  // Обновляем позицию для следующей проверки (если будем проверять дистанцию)

    if (m_map3DView)
    {
        m_map3DView->setWaypoints(m_currentMapData->waypoints);  // Обновляем вид
    }

    // Помечаем карту как измененную (активируем кнопки сохранения)
    if (m_saveMapAction) m_saveMapAction->setEnabled(true);
    if (m_saveMapAsAction) m_saveMapAsAction->setEnabled(true);
    // statusBar()->showMessage(tr("Точка записана: ID %1").arg(newWaypoint.id), 1000);
}

void MainWindow::onFocusOnPlayerButtonClicked()
{
    qCDebug(mainWindowLog) << "Focus on Player button clicked.";
    if (m_playerDataSource && m_playerDataSource->isHookSet())
    {
        QVector3D playerPosition = m_playerDataSource->currentPosition();
        if (m_map3DView)
        {
            m_map3DView->focusOnPlayer(playerPosition);
        }
        else
        {
            qCWarning(mainWindowLog) << "Map3DView is null, cannot focus.";
        }
    }
    else
    {
        QMessageBox::information(this, tr("Фокус на игроке"),
                                 tr("Не подключено к процессу или источник данных игрока недоступен."));
    }
}

void MainWindow::onMap3DViewWaypointsChanged(const QList<Waypoint> &waypoints)
{
    if (m_currentMapData)
    {
        qCDebug(mainWindowLog) << "Updating m_currentMapData->waypoints from Map3DView. Old count:"
                               << m_currentMapData->waypoints.size() << "New count:" << waypoints.size();
        m_currentMapData->waypoints = waypoints;
        // Возможно, здесь стоит установить флаг "изменено" для карты, чтобы активировать кнопку сохранения
        if (m_saveMapAction) m_saveMapAction->setEnabled(true);
        if (m_saveMapAsAction) m_saveMapAsAction->setEnabled(true);
    }
    else
    {
        qCWarning(mainWindowLog) << "onMap3DViewWaypointsChanged called but m_currentMapData is null!";
    }
}

void MainWindow::onSavePlayerPositionActionTriggered()
{
    if (!m_playerDataSource || !m_playerDataSource->isHookSet())
    {
        QMessageBox::warning(this, tr("Сохранение точки"), tr("Необходимо подключиться к процессу игры."));
        return;
    }

    if (!m_currentMapData)  // Проверка, что данные карты существуют
    {
        QMessageBox::warning(this, tr("Сохранение точки"), tr("Данные карты не загружены."));
        return;
    }

    // Если карта не была сохранена ни разу, предложим сначала сохранить карту.
    // Это нужно, чтобы было куда добавлять точку и чтобы пользователь не потерял несохраненную карту.
    if (m_currentMapFilePath.isEmpty())
    {
        QMessageBox::information(this, tr("Сохранение точки"),
                                 tr("Пожалуйста, сначала сохраните текущую карту (Файл -> Сохранить как...)."));
        onSaveMapAsActionTriggered();        // Предлагаем сохранить карту
        if (m_currentMapFilePath.isEmpty())  // Если пользователь отменил сохранение
        {
            qCInfo(mainWindowLog) << "Save Player Position: Map save cancelled, aborting point save.";
            return;
        }
    }

    QVector3D currentPlayerPos = m_playerDataSource->currentPosition();
    if (currentPlayerPos.isNull())
    {
        qCWarning(mainWindowLog) << "Cannot save player waypoint: current player position is null.";
        QMessageBox::warning(this, tr("Сохранение точки"), tr("Не удалось получить текущую позицию игрока."));
        return;
    }

    int newWaypointId = 1;
    if (m_currentMapData && !m_currentMapData->waypoints.isEmpty())
    {
        for (const auto &wp : m_currentMapData->waypoints)
        {
            if (wp.id >= newWaypointId)
            {
                newWaypointId = wp.id + 1;
            }
        }
    }

    Waypoint newWaypoint;
    newWaypoint.id = newWaypointId;
    newWaypoint.name = QString("PlayerSaved_WP_%1").arg(newWaypointId);
    newWaypoint.coordinates = currentPlayerPos;
    // newWaypoint.connectedWaypointIds остается пустым по умолчанию

    m_currentMapData->addWaypoint(newWaypoint);
    qCInfo(mainWindowLog) << "Saved player waypoint:" << newWaypoint.id << "at" << newWaypoint.coordinates;

    if (m_map3DView)
    {
        m_map3DView->setWaypoints(m_currentMapData->waypoints);  // Обновляем вид
    }

    // Помечаем карту как измененную (активируем кнопки сохранения)
    if (m_saveMapAction) m_saveMapAction->setEnabled(true);
    if (m_saveMapAsAction)
        m_saveMapAsAction->setEnabled(
            true);  // Это на случай, если карта была только что создана/загружена и еще не изменялась

    statusBar()->showMessage(tr("Точка персонажа сохранена: ID %1").arg(newWaypoint.id), 3000);
}

void MainWindow::updateUIBasedOnConnection(bool isConnected)
{
    if (m_connectToProcessAction) m_connectToProcessAction->setEnabled(!isConnected);
    if (m_focusOnPlayerButton) m_focusOnPlayerButton->setEnabled(isConnected);
    if (m_toggleRecordRouteAction)
        m_toggleRecordRouteAction->setEnabled(isConnected);  // Активируем кнопку записи только если подключены
    if (m_savePlayerPositionAction)                          // Добавляем управление активностью для новой кнопки
        m_savePlayerPositionAction->setEnabled(isConnected);
    if (m_addObstaclePointAction)  // <--- УПРАВЛЕНИЕ АКТИВНОСТЬЮ F2
        m_addObstaclePointAction->setEnabled(isConnected);

    if (!isConnected)
    {
        if (m_isRecordingRoute)  // Если отсоединились во время записи, останавливаем ее
        {
            m_recordRouteTimer->stop();
            m_isRecordingRoute = false;
            if (m_toggleRecordRouteAction)
            {
                m_toggleRecordRouteAction->setChecked(false);
                m_toggleRecordRouteAction->setText(tr("&Начать запись маршрута"));
            }
            qCInfo(mainWindowLog) << "Route recording stopped due to disconnection.";
        }
        if (m_positionUpdateTimer && m_positionUpdateTimer->isActive())
        {
            m_positionUpdateTimer->stop();
            qCInfo(mainWindowLog) << "Position update timer stopped.";
        }
        if (m_map3DView)
        {
            m_map3DView->updatePlayerPosition(QVector3D());
        }
        if (m_playerPositionConnection)
        {
            QObject::disconnect(m_playerPositionConnection);
        }
        if (m_memoryManager && m_memoryManager->isProcessOpen())
        {
            m_memoryManager->closeProcess();
            qCInfo(mainWindowLog) << "MemoryManager closed process due to disconnection.";
        }
    }
}

#ifdef Q_OS_WIN
// Включаем windows.h здесь, если не включили в .h и если он нужен только для nativeEvent
// #include <windows.h>

bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    if (eventType == "windows_generic_MSG" || eventType == "windows_dispatcher_MSG")  // Qt 5 / Qt 6
    {
        MSG *msg = static_cast<MSG *>(message);
        if (msg->message == WM_HOTKEY)
        {
            if (msg->wParam == GLOBAL_HOTKEY_ID_F1)
            {
                qCDebug(mainWindowLog) << "Global F1 hotkey pressed!";
                // Вызываем тот же слот, что и для действия меню
                // Убедимся, что окно активно или это не приведет к проблемам с модальными диалогами и т.д.
                // Для простоты пока прямой вызов.
                onSavePlayerPositionActionTriggered();
                *result = 0;  // Сообщаем, что обработали
                return true;  // Событие обработано
            }
            else if (msg->wParam == GLOBAL_HOTKEY_ID_F2)  // <--- ОБРАБОТКА F2
            {
                qCDebug(mainWindowLog) << "Global F2 hotkey pressed!";
                onAddObstaclePointActionTriggered();
                *result = 0;
                return true;
            }
        }
    }
    return QMainWindow::nativeEvent(eventType, message, result);
}
#else
// Заглушка для других ОС
bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    return QMainWindow::nativeEvent(eventType, message, result);
}
#endif

void MainWindow::showEvent(QShowEvent *event)
{
    QMainWindow::showEvent(event);  // Важно вызвать базовую реализацию
#ifdef Q_OS_WIN
    // Регистрация глобального хоткея F1 при показе окна
    if (!RegisterHotKey((HWND)this->winId(), GLOBAL_HOTKEY_ID_F1, 0, VK_F1))
    {
        qCWarning(mainWindowLog) << "[showEvent] Failed to register global hotkey F1. Error code:" << GetLastError();
    }
    else
    {
        qCInfo(mainWindowLog) << "[showEvent] Global hotkey F1 registered successfully.";
    }
    // Регистрация глобального хоткея F2
    if (!RegisterHotKey((HWND)this->winId(), GLOBAL_HOTKEY_ID_F2, 0, VK_F2))  // <--- РЕГИСТРАЦИЯ F2
    {
        qCWarning(mainWindowLog) << "[showEvent] Failed to register global hotkey F2. Error code:" << GetLastError();
    }
    else
    {
        qCInfo(mainWindowLog) << "[showEvent] Global hotkey F2 registered successfully.";
    }
#endif
}

void MainWindow::closeEvent(QCloseEvent *event)
{
#ifdef Q_OS_WIN
    // Разрегистрация глобального хоткея F1 при закрытии окна
    if (!UnregisterHotKey((HWND)this->winId(), GLOBAL_HOTKEY_ID_F1))
    {
        qCWarning(mainWindowLog) << "[closeEvent] Failed to unregister global hotkey F1. Error code:" << GetLastError();
        // Можно решить, стоит ли прерывать закрытие, если хоткей не разрегистрировался, но обычно нет.
    }
    else
    {
        qCInfo(mainWindowLog) << "[closeEvent] Global hotkey F1 unregistered successfully.";
    }
    // Разрегистрация глобального хоткея F2
    if (!UnregisterHotKey((HWND)this->winId(), GLOBAL_HOTKEY_ID_F2))  // <--- РАЗРЕГИСТРАЦИЯ F2
    {
        qCWarning(mainWindowLog) << "[closeEvent] Failed to unregister global hotkey F2. Error code:" << GetLastError();
    }
    else
    {
        qCInfo(mainWindowLog) << "[closeEvent] Global hotkey F2 unregistered successfully.";
    }
#endif
    QMainWindow::closeEvent(event);  // Важно вызвать базовую реализацию
}

// --- Начало блока кода для тестирования поиска пути ---

// Структура для ключа пространственной сетки
struct GridKey
{
    int x, y, z;
    bool operator<(const GridKey &other) const
    {
        if (x != other.x) return x < other.x;
        if (y != other.y) return y < other.y;
        return z < other.z;
    }
};

void MainWindow::onRunPathfindingTestActionTriggered()
{
    qCInfo(mainWindowLog) << "--- Pathfinding Test Started (Random 3D Cloud) ---";
    QElapsedTimer totalTestTimer;
    totalTestTimer.start();

    MapData testMapData;
    testMapData.mapName = "Pathfinding Test Map - Random 3D";
    testMapData.mapId = -2;
    testMapData.version = "1.0_random_3d_test";

    const int NUM_RANDOM_POINTS = 50000;
    const float MIN_X = -10000.0f, MAX_X = 10000.0f;
    const float MIN_Y = -10000.0f, MAX_Y = 10000.0f;
    const float MIN_Z = 0.0f, MAX_Z = 100.0f;
    int waypointIdCounter = 1;

    qCInfo(mainWindowLog) << "Generating" << NUM_RANDOM_POINTS << "random waypoints in a 3D cube...";
    QElapsedTimer pointGenerationTimer;
    pointGenerationTimer.start();

    for (int k = 0; k < NUM_RANDOM_POINTS; ++k)
    {
        Waypoint wp;
        wp.id = waypointIdCounter++;
        wp.coordinates.setX(MIN_X +
                            (static_cast<float>(QRandomGenerator::global()->generateDouble()) * (MAX_X - MIN_X)));
        wp.coordinates.setY(MIN_Y +
                            (static_cast<float>(QRandomGenerator::global()->generateDouble()) * (MAX_Y - MIN_Y)));
        wp.coordinates.setZ(MIN_Z +
                            (static_cast<float>(QRandomGenerator::global()->generateDouble()) * (MAX_Z - MIN_Z)));
        wp.name = QString("RandWP_%1").arg(wp.id);
        testMapData.addWaypoint(wp);
    }
    qint64 pointGenTimeMs = pointGenerationTimer.elapsed();
    qCInfo(mainWindowLog) << "Waypoint generation took" << pointGenTimeMs << "ms.";

    qCInfo(mainWindowLog) << "Generating connections using spatial grid and radius search...";
    QElapsedTimer connectionGenerationTimer;
    connectionGenerationTimer.start();

    const float CONNECTION_RADIUS = 300.0f;
    const float CONNECTION_RADIUS_SQR = CONNECTION_RADIUS * CONNECTION_RADIUS;
    const float CELL_SIZE = CONNECTION_RADIUS;

    QMap<GridKey, QList<int>> spatialGrid;
    auto getGridKey = [&](const QVector3D &coord)
    {
        return GridKey{static_cast<int>(std::floor(coord.x() / CELL_SIZE)),
                       static_cast<int>(std::floor(coord.y() / CELL_SIZE)),
                       static_cast<int>(std::floor(coord.z() / CELL_SIZE))};
    };

    for (const Waypoint &wp : testMapData.waypoints)
    {
        spatialGrid[getGridKey(wp.coordinates)].append(wp.id);
    }

    // Кэшируем указатели на Waypoint для быстрого доступа
    QMap<int, Waypoint *> waypointLookup;
    for (int idx = 0; idx < testMapData.waypoints.size(); ++idx)
    {
        waypointLookup[testMapData.waypoints[idx].id] = &testMapData.waypoints[idx];
    }

    int connectionsMade = 0;
    for (Waypoint &wp1 : testMapData.waypoints)
    {  // Новый цикл, итерируем по ссылкам напрямую
        GridKey centerKey = getGridKey(wp1.coordinates);

        for (int dz = -1; dz <= 1; ++dz)
        {
            for (int dy = -1; dy <= 1; ++dy)
            {
                for (int dx = -1; dx <= 1; ++dx)
                {
                    GridKey neighborCellKey = {centerKey.x + dx, centerKey.y + dy, centerKey.z + dz};
                    if (spatialGrid.contains(neighborCellKey))
                    {
                        const QList<int> &cellWaypoints = spatialGrid.value(neighborCellKey);
                        for (int neighborId : cellWaypoints)
                        {
                            if (wp1.id >= neighborId)
                                continue;  // Обрабатываем каждую пару (wp1, wp2) только один раз, где wp1.id < wp2.id

                            // Waypoint* wp2 = testMapData.findWaypointById(neighborId); // Старый медленный поиск
                            Waypoint *wp2 = waypointLookup.value(neighborId, nullptr);  // Быстрый поиск по ID
                            if (!wp2) continue;

                            // Вычисляем квадрат расстояния вручную для эффективности
                            QVector3D diff = wp1.coordinates - wp2->coordinates;
                            float distSq = QVector3D::dotProduct(diff, diff);

                            if (distSq <= CONNECTION_RADIUS_SQR)
                            {
                                // bool alreadyConnected1 = wp1.connectedWaypointIds.contains(wp2->id); // Эта проверка
                                // больше не нужна, т.к. пара обрабатывается 1 раз
                                wp1.connectedWaypointIds.insert(wp2->id);
                                wp2->connectedWaypointIds.insert(wp1.id);  // Симметричная связь
                                connectionsMade++;
                            }
                        }
                    }
                }
            }
        }
    }
    qint64 connectionGenTimeMs = connectionGenerationTimer.elapsed();
    qCInfo(mainWindowLog) << "Connection generation took" << connectionGenTimeMs
                          << "ms. Total connections pairs made:" << connectionsMade;

    // Выбор начальной и конечной точек
    int startNodeId = -1, goalNodeId = -1;
    QVector3D startTargetPos(MIN_X, MIN_Y, MIN_Z);
    QVector3D goalTargetPos(MAX_X, MAX_Y, MAX_Z);
    double minDistToStartSqr = std::numeric_limits<double>::max();
    double minDistToGoalSqr = std::numeric_limits<double>::max();

    if (testMapData.waypoints.isEmpty())
    {
        qCWarning(mainWindowLog) << "No waypoints generated, aborting A* test.";
        QMessageBox::warning(this, tr("Pathfinding Test Error"), tr("No waypoints were generated."));
        return;
    }

    // Если точек мало, можем просто взять первую и последнюю
    if (testMapData.waypoints.size() == 1)
    {
        startNodeId = testMapData.waypoints.first().id;
        goalNodeId = testMapData.waypoints.first().id;  // Путь к себе
    }
    else if (testMapData.waypoints.size() > 1)
    {
        for (const Waypoint &wp : testMapData.waypoints)
        {
            // Вычисляем квадрат расстояния вручную
            QVector3D diffToStart = wp.coordinates - startTargetPos;
            double distToStartSqr = static_cast<double>(QVector3D::dotProduct(diffToStart, diffToStart));
            if (distToStartSqr < minDistToStartSqr)
            {
                minDistToStartSqr = distToStartSqr;
                startNodeId = wp.id;
            }
            // Вычисляем квадрат расстояния вручную
            QVector3D diffToGoal = wp.coordinates - goalTargetPos;
            double distToGoalSqr = static_cast<double>(QVector3D::dotProduct(diffToGoal, diffToGoal));
            if (distToGoalSqr < minDistToGoalSqr)
            {
                minDistToGoalSqr = distToGoalSqr;
                goalNodeId = wp.id;
            }
        }
    }

    if (startNodeId == -1 || goalNodeId == -1 || startNodeId == goalNodeId)
    {
        qCWarning(mainWindowLog) << "Could not determine valid start/goal nodes. Using first and last if available.";
        // Fallback if specific targets not found or are same
        if (!testMapData.waypoints.isEmpty())
        {
            startNodeId = testMapData.waypoints.first().id;
            if (testMapData.waypoints.size() > 1)
            {
                goalNodeId = testMapData.waypoints.last().id;
            }
            else
            {
                goalNodeId = startNodeId;
            }
        }
        else
        {
            qCWarning(mainWindowLog) << "No waypoints to select start/goal from.";
            QMessageBox::warning(this, tr("Pathfinding Test Error"), tr("Could not select start/goal waypoints."));
            return;
        }
        if (startNodeId == goalNodeId && testMapData.waypoints.size() > 1)
        {  // try to find a different goal
            for (const auto &wp : testMapData.waypoints)
            {
                if (wp.id != startNodeId)
                {
                    goalNodeId = wp.id;
                    break;
                }
            }
        }
    }
    qCInfo(mainWindowLog) << "Selected Start Node ID:" << startNodeId << "Goal Node ID:" << goalNodeId;

    qCInfo(mainWindowLog) << "Running A* search...";
    QElapsedTimer searchTimer;
    searchTimer.start();
    QList<int> path = Core::Pathfinding::findPathAStar(testMapData, startNodeId, goalNodeId);  // <--- ИЗМЕНЕНИЕ ЗДЕСЬ
    qint64 searchTimeMs = searchTimer.elapsed();

    qCInfo(mainWindowLog) << "A* search function call took: " << searchTimeMs
                          << " ms (this is the value for the message box).";  // Дополнительный лог

    QString resultMessage = QString("Long distance path (start: %1, goal: %2): %3 Length: %4 waypoints.")
                                .arg(startNodeId)
                                .arg(goalNodeId)
                                .arg(path.isEmpty() ? "NOT found" : "Found")
                                .arg(path.size());
    if (!path.isEmpty())
    {
        // qCInfo(mainWindowLog) << resultMessage; // Уже сформировано выше
        QString pathToPrint;
        for (int k = 0; k < qMin(10, path.size()); ++k) pathToPrint += QString::number(path[k]) + " -> ";
        if (path.size() > 10) pathToPrint += "...";
        qCDebug(mainWindowLog) << "Path segment: " << pathToPrint;
    }

    // --- Дополнительные тесты на короткие дистанции ---
    QString shortTestResultsMessage;
    qint64 shortSearch100mTimeMs = -1;
    qint64 shortSearch1000mTimeMs = -1;

    if (testMapData.waypoints.size() > 1)
    {
        int randomStartIndex = QRandomGenerator::global()->bounded(testMapData.waypoints.size());
        const Waypoint &shortTestStartNode = testMapData.waypoints[randomStartIndex];
        int shortTestStartId = shortTestStartNode.id;

        auto findTargetNodeNear = [&](float targetDistance, const QString &distLabel) -> QPair<int, qint64>
        {
            int targetNodeId = -1;
            qint64 searchTime = -1;
            double closestDistDiff = std::numeric_limits<double>::max();
            int potentialTargetId = -1;

            for (const Waypoint &wp : testMapData.waypoints)
            {
                if (wp.id == shortTestStartId) continue;
                double dist = shortTestStartNode.coordinates.distanceToPoint(wp.coordinates);
                double diff = std::fabs(dist - targetDistance);
                if (diff < closestDistDiff)
                {
                    closestDistDiff = diff;
                    potentialTargetId = wp.id;
                }
            }

            if (potentialTargetId != -1)
            {
                targetNodeId = potentialTargetId;
                qCInfo(mainWindowLog)
                    << QString("Running A* for %1 (Start: %2, Goal: %3, Approx Dist: %4, Actual Dist: %5)")
                           .arg(distLabel)
                           .arg(shortTestStartId)
                           .arg(targetNodeId)
                           .arg(targetDistance)
                           .arg(shortTestStartNode.coordinates.distanceToPoint(
                               testMapData.findWaypointById(targetNodeId)->coordinates));
                QElapsedTimer shortSearchTimer;
                shortSearchTimer.start();
                QList<int> shortPath = Core::Pathfinding::findPathAStar(testMapData, shortTestStartId,
                                                                        targetNodeId);  // <--- ИЗМЕНЕНИЕ ЗДЕСЬ
                searchTime = shortSearchTimer.elapsed();
                shortTestResultsMessage +=
                    QString("\n%1 path (start: %2, goal: %3): %4 Length: %5 waypoints. Time: %6 ms.")
                        .arg(distLabel)
                        .arg(shortTestStartId)
                        .arg(targetNodeId)
                        .arg(shortPath.isEmpty() ? "NOT found" : "Found")
                        .arg(shortPath.size())
                        .arg(searchTime);
            }
            else
            {
                shortTestResultsMessage +=
                    QString("\nCould not find a suitable target node for %1 test.").arg(distLabel);
            }
            return {targetNodeId, searchTime};
        };

        QPair<int, qint64> result100m = findTargetNodeNear(100.0f, "100m");
        shortSearch100mTimeMs = result100m.second;

        QPair<int, qint64> result1000m = findTargetNodeNear(1000.0f, "1000m");
        shortSearch1000mTimeMs = result1000m.second;
    }
    // --- Конец дополнительных тестов ---

    qint64 totalTimeMs = totalTestTimer.elapsed();
    qCInfo(mainWindowLog) << "--- Pathfinding Test Finished. Total time:" << totalTimeMs << "ms ---";
    QMessageBox::information(this, tr("Pathfinding Test Results"),
                             QString("Total Waypoints: %1\\n\\n"
                                     "Point Generation Time: %2 ms\\n"
                                     "Connection Generation Time: %3 ms\\n"
                                     "A* Search Time (long dist): %4 ms\\n"
                                     "Result (long dist): %5\\n"
                                     "%6\\n\\n"  // Место для результатов коротких тестов
                                     "Total Test Duration: %7 ms")
                                 .arg(testMapData.waypoints.size())
                                 .arg(pointGenTimeMs)
                                 .arg(connectionGenTimeMs)
                                 .arg(searchTimeMs)
                                 .arg(resultMessage)            // Основной результат (длинный путь)
                                 .arg(shortTestResultsMessage)  // Результаты коротких тестов
                                 .arg(totalTimeMs));

    // Чтобы отобразить эти точки, можно сделать так:
    if (!path.isEmpty() && m_map3DView)
    {
        MapData pathDisplayMap;
        pathDisplayMap.mapName = "Found Path Display";
        for (int wpId : path)
        {
            const Waypoint *wp = testMapData.findWaypointById(wpId);
            if (wp) pathDisplayMap.addWaypoint(*wp);  // Добавляем копию
        }
        // Соединим точки пути последовательно для отображения линий
        if (pathDisplayMap.waypoints.size() > 1)
        {
            for (int i = 0; i < pathDisplayMap.waypoints.size() - 1; ++i)
            {
                Waypoint &wpA = pathDisplayMap.waypoints[i];
                Waypoint &wpB = pathDisplayMap.waypoints[i + 1];
                wpA.connectedWaypointIds.clear();  // Убираем старые связи от генерации сетки
                wpB.connectedWaypointIds.clear();
                wpA.connectedWaypointIds.insert(wpB.id);
                wpB.connectedWaypointIds.insert(wpA.id);  // Делаем двустороннюю связь для корректной отрисовки линий
            }
        }

        m_currentMapData->clear();           // Очищаем текущую карту редактора
        *m_currentMapData = pathDisplayMap;  // Копируем карту с путем
        m_currentMapFilePath.clear();        // Сбрасываем путь к файлу
        m_map3DView->setWaypoints(m_currentMapData->waypoints);
        m_map3DView->setObstacles(m_currentMapData->obstacles);  // <--- Добавлено для отображения препятствий
        qCWarning(mainWindowLog)
            << "TODO: Implement obstacle rendering in Map3DView!";  // Этот TODO теперь можно будет убрать или обновить

        if (m_saveMapAction) m_saveMapAction->setEnabled(false);
        if (m_saveMapAsAction) m_saveMapAsAction->setEnabled(true);
        statusBar()->showMessage(tr("Отображен результат теста поиска пути."), 3000);
        setWindowTitle(tr("Map Editor - Pathfinding Test Result"));
    }
}
// --- Конец блока кода для тестирования поиска пути ---

// --- Начало блока кода для теста с препятствиями ---

void MainWindow::onRunObstacleScenarioTestTriggered()
{
    qCDebug(mainWindowLog) << "onRunObstacleScenarioTestTriggered called";
    QElapsedTimer totalTimer;
    totalTimer.start();

    MapData testMapData;
    testMapData.mapName = "Obstacle Scenario Test Map";
    testMapData.mapId = -3;
    testMapData.version = "1.0_obstacle_scenario_test";

    // 1. Создание путевых точек
    qCInfo(mainWindowLog) << "Creating waypoints for fence scenario...";
    Waypoint wpTL(1, "TL", QVector3D(0, 100, 0));
    Waypoint wpTR(2, "TR", QVector3D(100, 100, 0));
    Waypoint wpBL(3, "BL", QVector3D(0, 0, 0));
    Waypoint wpBR(4, "BR", QVector3D(100, 0, 0));
    Waypoint wpC(5, "C", QVector3D(50, 50, 0));  // Центр

    testMapData.addWaypoint(wpTL);
    testMapData.addWaypoint(wpTR);
    testMapData.addWaypoint(wpBL);
    testMapData.addWaypoint(wpBR);
    testMapData.addWaypoint(wpC);
    qCInfo(mainWindowLog) << "Waypoints created:" << testMapData.waypoints.size();

    // 2. Создание препятствий (заборчиков)
    qCInfo(mainWindowLog) << "Creating obstacles (fences)...";
    testMapData.obstacles.clear();
    testMapData.obstacles.append(Obstacle(QVector3D(-5, 52, -5), QVector3D(52, 58, 20), 1, "Fence_TL-C"));
    testMapData.obstacles.append(Obstacle(QVector3D(48, 52, -5), QVector3D(105, 58, 20), 2, "Fence_TR-C"));
    testMapData.obstacles.append(
        Obstacle(QVector3D(-5, 45, -5), QVector3D(49, 55, 20), 3, "Fence_BLC_Blocks_BRC_Open"));

    qCInfo(mainWindowLog) << "Obstacles created:" << testMapData.obstacles.size();

    // 3. Генерация связей с учетом LoS
    qCInfo(mainWindowLog) << "Generating connections with LoS check...";
    QElapsedTimer connTimer;
    connTimer.start();
    const float SCENARIO_CONNECTION_RADIUS =
        150.0f;  // Увеличим немного для надежности соединений по диагонали и к центру

    QMap<int, Waypoint *> waypointLookupScenario;
    for (int idx = 0; idx < testMapData.waypoints.size(); ++idx)
    {
        waypointLookupScenario[testMapData.waypoints[idx].id] = &testMapData.waypoints[idx];
    }
    int connectionsMadeScenario = 0;
    for (Waypoint &wp1 : testMapData.waypoints)
    {
        for (Waypoint &wp2 : testMapData.waypoints)
        {
            if (wp1.id >= wp2.id) continue;  // Обрабатываем каждую пару один раз

            if (wp1.coordinates.distanceToPoint(wp2.coordinates) <= SCENARIO_CONNECTION_RADIUS)
            {
                // ИЗМЕНЕНИЕ: Используем Core::LoS::hasLineOfSightAABB
                if (Core::LoS::hasLineOfSightAABB(wp1.coordinates, wp2.coordinates, testMapData.obstacles))
                {
                    wp1.connectedWaypointIds.insert(wp2.id);
                    wp2.connectedWaypointIds.insert(wp1.id);
                    connectionsMadeScenario++;
                    qCDebug(mainWindowLog) << "Connected (LoS OK):" << wp1.name << "<->" << wp2.name;
                }
                else
                {
                    qCDebug(mainWindowLog) << "No LoS between:" << wp1.name << "and" << wp2.name;
                }
            }
        }
    }
    qint64 connTimeMs = connTimer.elapsed();
    qCInfo(mainWindowLog) << "Connection generation for scenario took" << connTimeMs
                          << "ms. Connections:" << connectionsMadeScenario;

    // 4. Поиск пути A* (например, от TL до C)
    int startNodeIdScenario = wpTL.id;
    int goalNodeIdScenario = wpC.id;
    qCInfo(mainWindowLog) << "Running A* for scenario (Start:" << wpTL.name << ", Goal:" << wpC.name << ")...";
    QElapsedTimer searchTimerScenario;
    searchTimerScenario.start();
    QList<int> pathScenario = Core::Pathfinding::findPathAStar(testMapData, startNodeIdScenario, goalNodeIdScenario);
    qint64 searchTimeMsScenario = searchTimerScenario.elapsed();

    QString scenarioResultMessage;
    if (!pathScenario.isEmpty())
    {
        QString pathStr;
        for (int nodeId : pathScenario)
        {
            const Waypoint *wp = waypointLookupScenario.value(nodeId);
            pathStr += (wp ? wp->name : QString::number(nodeId)) + " -> ";
        }
        if (pathStr.endsWith(" -> ")) pathStr.chop(4);
        scenarioResultMessage =
            QString("Scenario Path FOUND! Length: %1. Path: [%2]").arg(pathScenario.size()).arg(pathStr);
        qCInfo(mainWindowLog) << scenarioResultMessage;
    }
    else
    {
        scenarioResultMessage = "Scenario Path NOT found.";
        qCWarning(mainWindowLog) << scenarioResultMessage;
    }
    qCInfo(mainWindowLog) << "A* search for scenario took:" << searchTimeMsScenario << "ms.";

    qint64 totalScenarioTimeMs = totalTimer.elapsed();
    qCInfo(mainWindowLog) << "--- Obstacle Scenario Test Finished. Total time:" << totalScenarioTimeMs << "ms ---";

    QMessageBox::information(this, tr("Obstacle Scenario Test Results"),
                             QString("Waypoints: %1, Obstacles: %2\nConnection Time: %3 ms, Connections Made: "
                                     "%4\nSearch Time: %5 ms\n%6\n\nTotal Test Duration: %7 ms")
                                 .arg(testMapData.waypoints.size())
                                 .arg(testMapData.obstacles.size())
                                 .arg(connTimeMs)
                                 .arg(connectionsMadeScenario)
                                 .arg(searchTimeMsScenario)
                                 .arg(scenarioResultMessage)
                                 .arg(totalScenarioTimeMs));

    // Отображение результата
    m_currentMapData->clear();
    *m_currentMapData = testMapData;  // Копируем всю карту с точками и препятствиями
    m_currentMapFilePath.clear();
    m_map3DView->setWaypoints(m_currentMapData->waypoints);
    m_map3DView->setObstacles(m_currentMapData->obstacles);
    qCWarning(mainWindowLog) << "TODO: Implement precise obstacle rendering and LoS in Map3DView!";

    if (m_saveMapAction) m_saveMapAction->setEnabled(false);
    if (m_saveMapAsAction) m_saveMapAsAction->setEnabled(true);
    statusBar()->showMessage(tr("Отображен результат теста с препятствиями."), 3000);
    setWindowTitle(tr("Map Editor - Obstacle Test Result"));
}

// --- Конец блока кода для теста с препятствиями ---

void MainWindow::onNewMap()
{
    qCDebug(mainWindowLog) << "onNewMap called";
    // Возможно, стоит спросить пользователя о сохранении текущей карты, если она изменена

    m_map3DView->clearMapDisplayData();
    m_currentMapData->clear();
    m_currentMapFilePath.clear();
    setWindowTitle("MapEditor - New Map");

    m_map3DView->setWaypoints(m_currentMapData->waypoints);
    m_map3DView->setObstacles(m_currentMapData->obstacles);

    updateWaypointList();
    updateConnectionsTextEdit();
}

void MainWindow::onClearWaypointsTriggered()
{
    qCDebug(mainWindowLog) << "onClearWaypointsTriggered called";
    if (QMessageBox::question(this, "Clear Waypoints", "Are you sure you want to clear all waypoints and obstacles?",
                              QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
    {
        m_map3DView->clearMapDisplayData();
        m_currentMapData->clear();

        m_map3DView->setWaypoints(m_currentMapData->waypoints);
        m_map3DView->setObstacles(m_currentMapData->obstacles);

        updateWaypointList();
        updateConnectionsTextEdit();
        updateWindowTitle();
        qCDebug(mainWindowLog) << "All waypoints and obstacles cleared.";
    }
}

// Если updateWaypointList, updateConnectionsTextEdit, updateWindowTitle не существуют,
// их нужно либо реализовать, либо удалить их вызовы.
// Примерные заглушки, если они нужны:

void MainWindow::updateWaypointList()
{
    qCDebug(mainWindowLog) << "MainWindow::updateWaypointList() called - (Not Implemented)";
    // Логика обновления списка путевых точек в UI
}

void MainWindow::updateConnectionsTextEdit()
{
    qCDebug(mainWindowLog) << "MainWindow::updateConnectionsTextEdit() called - (Not Implemented)";
    // Логика обновления текстового поля соединений в UI
}

void MainWindow::updateWindowTitle()
{
    qCDebug(mainWindowLog) << "MainWindow::updateWindowTitle() called - (Not Implemented)";
    // Логика обновления заголовка окна, например, добавление '*' если есть несохраненные изменения
    QString title = "MapEditor";
    if (!m_currentMapFilePath.isEmpty())
    {
        title += " - " + QFileInfo(m_currentMapFilePath).fileName();
    }
    // if (isModified) title += "*"; // Нужен флаг isModified
    setWindowTitle(title);
}

void MainWindow::onAddObstaclePointActionTriggered()
{
    qCDebug(mainWindowLog) << "onAddObstaclePointActionTriggered (F2) called.";
    if (!m_playerDataSource || !m_playerDataSource->isHookSet())
    {
        QMessageBox::warning(this, tr("Добавление точки препятствия"), tr("Необходимо подключиться к процессу игры."));
        return;
    }

    if (!m_map3DView)  // Проверка, что Map3DView существует
    {
        qCWarning(mainWindowLog) << "Map3DView is null, cannot add obstacle point.";
        QMessageBox::critical(this, tr("Ошибка"), tr("Компонент 3D вида не инициализирован."));
        return;
    }

    QVector3D currentPlayerPos = m_playerDataSource->currentPosition();
    if (currentPlayerPos.isNull())
    {
        qCWarning(mainWindowLog) << "Cannot add obstacle point: current player position is null.";
        QMessageBox::warning(this, tr("Добавление точки препятствия"),
                             tr("Не удалось получить текущую позицию игрока."));
        return;
    }

    m_map3DView->addObstaclePointAtPlayerPosition(currentPlayerPos);
    statusBar()->showMessage(tr("Точка препятствия добавлена."), 3000);
    qCInfo(mainWindowLog) << "Obstacle point added via F2 at WoW coords:" << currentPlayerPos;
}

// --- Слоты для BugPathfinder теста ---

void MainWindow::onSetBugTestStart()
{
    qCDebug(mainWindowLog) << "Set Bug Test Start Point action triggered.";
    m_selectingBugTestStartPoint = true;
    m_selectingBugTestGoalPoint = false;
    statusBar()->showMessage(tr("Кликните на карту, чтобы выбрать начальную точку для Bug теста."), 3000);
    // Возможно, стоит изменить курсор или как-то визуально подсказать пользователю
}

void MainWindow::onSetBugTestGoal()
{
    qCDebug(mainWindowLog) << "Set Bug Test Goal Point action triggered.";
    m_selectingBugTestGoalPoint = true;
    m_selectingBugTestStartPoint = false;
    statusBar()->showMessage(tr("Кликните на карту, чтобы выбрать конечную точку для Bug теста."), 3000);
}

void MainWindow::onRunBugTest()
{
    qCDebug(mainWindowLog) << "Run Bug Test action triggered.";
    if (m_bugTestStartPoint.isNull() || m_bugTestGoalPoint.isNull())
    {
        QMessageBox::warning(this, tr("Запуск Bug теста"),
                             tr("Пожалуйста, сначала выберите начальную и конечную точки."));
        return;
    }

    if (!m_currentMapData)
    {
        QMessageBox::warning(this, tr("Запуск Bug теста"), tr("Данные карты не загружены."));
        return;
    }
    if (!m_map3DView)
    {
        qCritical(mainWindowLog) << "m_map3DView is null in onRunBugTest. Cannot proceed.";
        QMessageBox::critical(this, tr("Ошибка"), tr("Компонент 3D вида не инициализирован."));
        return;
    }

    const QList<Obstacle> &obstacles = m_currentMapData->obstacles;
    qCInfo(mainWindowLog) << "Starting BugPathfinder with Start:" << m_bugTestStartPoint
                          << "Goal:" << m_bugTestGoalPoint << "Obstacles count:" << obstacles.size();

    m_bugPathfinder.reset();
    m_bugPathCalculatedPath.clear();
    m_map3DView->clearBugTestData();
    m_map3DView->setBugTestMarkers(m_bugTestStartPoint, m_bugTestGoalPoint);
    m_map3DView->setBugMLine(m_bugTestStartPoint, m_bugTestGoalPoint);
    m_map3DView->setCurrentBugPosition(m_bugTestStartPoint);  // Начальная позиция

    // Вызываем findPath, который теперь void. Состояние проверяем после.
    m_bugPathfinder.findPath(m_bugTestStartPoint, m_bugTestGoalPoint, obstacles, m_currentMapData->waypoints);

    Core::Pathfinding::BugPathState initialState = m_bugPathfinder.getCurrentState();

    if (initialState == Core::Pathfinding::BugPathState::PATH_FOUND)
    {
        qCInfo(mainWindowLog) << "BugPathfinder found path immediately (e.g. direct LoS or already at goal).";
        // Сигналы pathFound/pathNotFound должны сработать из findPath, обновляя UI
        // Обновим состояние кнопок здесь на всякий случай, если сигналы не успеют обработаться до конца этого слота
        onBugPathFound(m_bugPathfinder.getCurrentPath());  // Передаем путь, если он есть
    }
    else if (initialState != Core::Pathfinding::BugPathState::PATH_NOT_FOUND)
    {
        m_bugTestTimer.start(100);  // Интервал таймера для шагов Bug алгоритма
        statusBar()->showMessage(tr("Bug тест запущен..."), 3000);
        qCInfo(mainWindowLog) << "BugPathfinder test started. Timer initiated for step-by-step execution.";
        if (m_setBugTestStartAction) m_setBugTestStartAction->setEnabled(false);
        if (m_setBugTestGoalAction) m_setBugTestGoalAction->setEnabled(false);
        if (m_runBugTestAction) m_runBugTestAction->setEnabled(false);
        if (m_resetBugTestAction) m_resetBugTestAction->setEnabled(true);
    }
    else  // initialState == Core::Pathfinding::BugPathState::PATH_NOT_FOUND
    {
        qCWarning(mainWindowLog)
            << "BugPathfinder is already in a final state after findPath call, timer not started. State: "
            << static_cast<int>(initialState);
        statusBar()->showMessage(tr("Bug тест: Путь не найден (немедленно)."), 3000);
        onBugPathNotFound();
        // Кнопки обновятся в onBugPathFound/onBugPathNotFound
    }
}

void MainWindow::onResetBugTest()
{
    qCDebug(mainWindowLog) << "Reset Bug Test action triggered.";
    m_bugTestTimer.stop();

    m_bugTestStartPoint = QVector3D();
    m_bugTestGoalPoint = QVector3D();
    m_selectingBugTestStartPoint = false;
    m_selectingBugTestGoalPoint = false;
    m_bugPathCalculatedPath.clear();

    m_bugPathfinder.reset();

    if (m_map3DView)
    {  // Проверка m_map3DView
        m_map3DView->clearBugTestData();
    }

    statusBar()->showMessage(tr("Bug тест сброшен. Выберите новые точки."), 3000);
    qCInfo(mainWindowLog) << "BugPathfinder test reset.";

    if (m_setBugTestStartAction) m_setBugTestStartAction->setEnabled(true);
    if (m_setBugTestGoalAction) m_setBugTestGoalAction->setEnabled(true);
    // m_runBugTestAction должен быть false до тех пор, пока не выбраны обе точки
    if (m_runBugTestAction)
        m_runBugTestAction->setEnabled(!m_bugTestStartPoint.isNull() && !m_bugTestGoalPoint.isNull());
    if (m_resetBugTestAction) m_resetBugTestAction->setEnabled(true);
}

void MainWindow::onBugTestTimerTimeout()
{
    if (!m_currentMapData || !m_map3DView)  // Проверка m_map3DView
    {
        qCWarning(mainWindowLog) << "BugTestTimerTimeout: No map data or Map3DView, stopping timer.";
        m_bugTestTimer.stop();
        onBugPathNotFound();
        return;
    }

    m_bugPathfinder.update();  // update() теперь не принимает аргументов
    QVector3D currentPos = m_bugPathfinder.getCurrentPosition();
    if (!currentPos.isNull())
    {
        m_bugPathCalculatedPath.append(currentPos);
    }

    m_map3DView->setCurrentBugPosition(currentPos);
    m_map3DView->setBugPath(m_bugPathCalculatedPath);
    m_map3DView->setBugHitPoint(m_bugPathfinder.getHitPoint());

    Core::Pathfinding::BugPathState stateAfterUpdate = m_bugPathfinder.getCurrentState();
    if (stateAfterUpdate == Core::Pathfinding::BugPathState::PATH_FOUND ||
        stateAfterUpdate ==
            Core::Pathfinding::BugPathState::PATH_NOT_FOUND)  // Используем PATH_NOT_FOUND для ошибок/застреваний
    {
        qCInfo(mainWindowLog) << "BugTestTimerTimeout: Path search concluded in update. State:"
                              << static_cast<int>(stateAfterUpdate);
        m_bugTestTimer.stop();
        // Сигналы onBugPathFound/onBugPathNotFound должны были быть вызваны из BugPathfinder
        // и они обновят состояние кнопок и statusBar.
        // Если BugPathfinder не эмитит сигнал при завершении через update(), то вызываем здесь:
        if (stateAfterUpdate == Core::Pathfinding::BugPathState::PATH_FOUND)
        {
            // onBugPathFound(m_bugPathfinder.getCurrentPath()); // Сигнал должен был сработать
        }
        else
        {
            // onBugPathNotFound(); // Сигнал должен был сработать
        }
    }
}

void MainWindow::onBugPathFound(const QList<QVector3D> &path)
{
    qCInfo(mainWindowLog) << "BugPathfinder: Path FOUND! Length:" << path.size();
    m_bugTestTimer.stop();
    m_bugPathCalculatedPath = path;  // Используем getCurrentPath() если path пустой

    if (m_map3DView)
    {
        m_map3DView->setBugPath(m_bugPathCalculatedPath.isEmpty() ? m_bugPathfinder.getCurrentPath()
                                                                  : m_bugPathCalculatedPath);
        m_map3DView->setCurrentBugPosition(m_bugPathfinder.getCurrentPosition());
        m_map3DView->setBugHitPoint(QVector3D());  // Сбрасываем хитпоинт, т.к. путь найден
    }

    statusBar()->showMessage(tr("Bug тест: Путь найден! Длина: %1 точек.").arg(m_bugPathCalculatedPath.size()), 5000);

    if (m_setBugTestStartAction) m_setBugTestStartAction->setEnabled(true);
    if (m_setBugTestGoalAction) m_setBugTestGoalAction->setEnabled(true);
    if (m_runBugTestAction)
        m_runBugTestAction->setEnabled(!m_bugTestStartPoint.isNull() && !m_bugTestGoalPoint.isNull());
    if (m_resetBugTestAction) m_resetBugTestAction->setEnabled(true);
}

void MainWindow::onBugPathNotFound()
{
    Core::Pathfinding::BugPathState finalState = m_bugPathfinder.getCurrentState();
    qCWarning(mainWindowLog) << "BugPathfinder: Path NOT FOUND. Final state:" << static_cast<int>(finalState);
    m_bugTestTimer.stop();

    // Обновляем путь тем, что есть, даже если он не полный
    m_bugPathCalculatedPath = m_bugPathfinder.getCurrentPath();

    if (m_map3DView)
    {
        m_map3DView->setBugPath(m_bugPathCalculatedPath);
        m_map3DView->setCurrentBugPosition(m_bugPathfinder.getCurrentPosition());
        m_map3DView->setBugHitPoint(m_bugPathfinder.getHitPoint());  // Показываем последний хитпоинт
    }

    // Сообщения теперь более общие, так как Stuck и Error состояний больше нет
    if (finalState == Core::Pathfinding::BugPathState::PATH_NOT_FOUND)
    {
        statusBar()->showMessage(tr("Bug тест: Путь не найден или ошибка."), 5000);
    }
    else  // На случай если сюда попали с другим состоянием, хотя не должны
    {
        statusBar()->showMessage(
            tr("Bug тест: Не удалось найти путь (состояние: %1).").arg(static_cast<int>(finalState)), 5000);
    }

    if (m_setBugTestStartAction) m_setBugTestStartAction->setEnabled(true);
    if (m_setBugTestGoalAction) m_setBugTestGoalAction->setEnabled(true);
    if (m_runBugTestAction)
        m_runBugTestAction->setEnabled(!m_bugTestStartPoint.isNull() && !m_bugTestGoalPoint.isNull());
    if (m_resetBugTestAction) m_resetBugTestAction->setEnabled(true);
}

void MainWindow::onBugStateChanged(Core::Pathfinding::BugPathState newState)
{
    QString stateString;
    switch (newState)
    {
        case Core::Pathfinding::BugPathState::IDLE:
            stateString = tr("Ожидание");
            break;
        case Core::Pathfinding::BugPathState::MOVING_TO_GOAL:
            stateString = tr("Движение к цели");
            break;
        case Core::Pathfinding::BugPathState::FOLLOWING_OBSTACLE:
            stateString = tr("Обход препятствия");
            break;
        case Core::Pathfinding::BugPathState::LEAVING_OBSTACLE:  // Добавлено, если используется
            stateString = tr("Покидание препятствия");
            break;
        case Core::Pathfinding::BugPathState::PATH_FOUND:
            stateString = tr("Цель достигнута");
            break;
        case Core::Pathfinding::BugPathState::PATH_NOT_FOUND:
            stateString = tr("Путь не найден/Ошибка");
            break;
        default:
            stateString = tr("Неизвестное состояние (%1)").arg(static_cast<int>(newState));
            break;
    }
    qCDebug(mainWindowLog) << "BugPathfinder state changed to:" << stateString << "(" << static_cast<int>(newState)
                           << ")";
    statusBar()->showMessage(tr("Bug тест Состояние: %1").arg(stateString), 2000);

    if (m_map3DView)
    {
        m_map3DView->setBugHitPoint(m_bugPathfinder.getHitPoint());
        // TODO: m_map3DView->setBugCurrentFollowingEdge(m_bugPathfinder.getCurrentFollowEdge()); // Для отладки обхода
        // Обновляем M-Line, если агент начал следовать по препятствию, она могла измениться (хотя в Bug2 M-Line
        // статична) if (newState == Core::Pathfinding::BugPathState::FollowingObstacle || newState ==
        // Core::Pathfinding::BugPathState::MovingToGoal) {
        //    m_map3DView->setBugMLine(m_bugPathfinder.getStartPoint(), m_bugPathfinder.getGoalPoint());
        // }
    }
}

void MainWindow::onMapClickedForBugTest(const QVector3D &position, Qt::MouseButton button)
{
    qCDebug(mainWindowLog) << "Map clicked for Bug Test. Position:" << position << "Button:" << button;

    if (button == Qt::LeftButton)
    {
        if (m_selectingBugTestStartPoint)
        {
            m_bugTestStartPoint = position;
            m_selectingBugTestStartPoint = false;
            qCInfo(mainWindowLog) << "Bug Test Start Point set to:" << m_bugTestStartPoint;
            statusBar()->showMessage(tr("Начальная точка для Bug теста установлена: %1, %2, %3")
                                         .arg(position.x())
                                         .arg(position.y())
                                         .arg(position.z()),
                                     3000);
            // TODO: Отобразить точку старта в Map3DView
            // m_map3DView->setBugTestStartMarker(m_bugTestStartPoint);

            if (!m_bugTestGoalPoint.isNull())
            {  // Если цель уже выбрана, активируем кнопку запуска
                if (m_runBugTestAction) m_runBugTestAction->setEnabled(true);
            }
        }
        else if (m_selectingBugTestGoalPoint)
        {
            m_bugTestGoalPoint = position;
            m_selectingBugTestGoalPoint = false;
            qCInfo(mainWindowLog) << "Bug Test Goal Point set to:" << m_bugTestGoalPoint;
            statusBar()->showMessage(tr("Конечная точка для Bug теста установлена: %1, %2, %3")
                                         .arg(position.x())
                                         .arg(position.y())
                                         .arg(position.z()),
                                     3000);
            // TODO: Отобразить точку цели в Map3DView
            // m_map3DView->setBugTestGoalMarker(m_bugTestGoalPoint);

            if (!m_bugTestStartPoint.isNull())
            {  // Если старт уже выбран, активируем кнопку запуска
                if (m_runBugTestAction) m_runBugTestAction->setEnabled(true);
            }
        }
        else
        {
            qCDebug(mainWindowLog) << "Map clicked, but not selecting start or goal for Bug Test.";
        }
    }
    else if (button == Qt::RightButton)  // Отмена выбора правой кнопкой
    {
        if (m_selectingBugTestStartPoint || m_selectingBugTestGoalPoint)
        {
            m_selectingBugTestStartPoint = false;
            m_selectingBugTestGoalPoint = false;
            statusBar()->showMessage(tr("Выбор точки для Bug теста отменен."), 2000);
            qCDebug(mainWindowLog) << "Bug test point selection cancelled by right click.";
        }
    }
}

void MainWindow::initializeMpqManager()
{
    qCDebug(mainWindowLog) << "Attempting to initialize MpqManager...";
    QSettings settings("MDBot", "MapEditor");
    // Ключ был "gamePath" в старом коде initializeMpqManager,
    // а в новом handleMpqInitializationFinished используется "GamePath". Приводим к одному виду.
    QString lastGamePath = settings.value("GamePath").toString();

    if (!lastGamePath.isEmpty() && QDir(lastGamePath).exists())
    {
        qCInfo(mainWindowLog) << "Found last game path in settings:" << lastGamePath;
        m_statusBar->showMessage(tr("Попытка загрузки MPQ из: %1... (может занять время)").arg(lastGamePath));

        // Запускаем инициализацию асинхронно
        QFuture<QPair<MpqManager*, QString>> future = QtConcurrent::run([lastGamePath, this]() { // Захватываем this для логгера
            qCDebug(mainWindowLog) << "QtConcurrent: Starting MpqManager initialization for" << lastGamePath;
            MpqManager* manager = new MpqManager(lastGamePath); // <-- Передаем путь в конструктор
            if (manager->initialize()) { // <-- Вызываем initialize() без аргументов
                qCDebug(mainWindowLog) << "QtConcurrent: MpqManager initialized successfully for" << lastGamePath;
                return qMakePair(manager, lastGamePath);
            } else {
                qCWarning(mainWindowLog) << "QtConcurrent: Failed to initialize MpqManager for" << lastGamePath;
                delete manager; // Очищаем, если инициализация не удалась
                return qMakePair(static_cast<MpqManager*>(nullptr), lastGamePath);
            }
        });
        m_mpqWatcher->setFuture(future);
    }
    else
    {
        qCWarning(mainWindowLog) << "No valid game path found in settings or path does not exist. Prompting user.";
        promptForGamePathAndInitialize(true);
    }
}

// Новый слот для обработки результата асинхронной инициализации
void MainWindow::handleMpqInitializationFinished(MpqManager *initializedManager, const QString &triedPath)
{
    qCDebug(mainWindowLog) << "handleMpqInitializationFinished called for path:" << triedPath
                           << "Manager valid:" << (initializedManager != nullptr);

    if (initializedManager)
    {
        m_mpqManager = initializedManager;
        m_gamePath = triedPath;
        m_statusBar->showMessage(tr("MPQ архивы успешно загружены из: %1").arg(m_gamePath), 5000);
        qCInfo(mainWindowLog) << "MpqManager successfully initialized with path:" << m_gamePath;

        // Сохраняем успешный путь
        QSettings settings("MDBot", "MapEditor");
        settings.setValue("GamePath", m_gamePath);

        // Обновляем виджет MPQ менеджера (если он есть и используется)
        if (m_mpqManagerWidget)
        {
            m_mpqManagerWidget->setMpqManager(m_mpqManager);
        }
        // Инициализируем другие зависимые компоненты
        initializeMapDataManager();
    }
    else
    {
        m_statusBar->showMessage(tr("Не удалось загрузить MPQ архивы из: %1").arg(triedPath), 5000);
        qCWarning(mainWindowLog) << "Failed to initialize MpqManager with path:" << triedPath;

        // Если это была попытка с путем из настроек, и она провалилась,
        // то показываем диалог выбора пути.
        // Мы можем проверить, был ли это "автоматический" запуск, сравнив triedPath с m_gamePath,
        // но проще передать флаг или определить по состоянию, что это первая попытка.
        // В данном случае, если m_mpqManager все еще nullptr, значит это первая неудачная попытка.
        if (!m_mpqManager)
        {                                           // Проверяем, не был ли менеджер уже успешно инициализирован ранее
            promptForGamePathAndInitialize(false);  // false - не первая попытка (первая была из настроек и провалилась)
        }
        else
        {
            // Если менеджер уже был, а новая попытка (например, через диалог) не удалась, просто сообщаем.
            QMessageBox::warning(this, tr("Ошибка загрузки MPQ"),
                                 tr("Не удалось загрузить MPQ архивы из указанного пути: %1").arg(triedPath));
        }
    }
}

void MainWindow::promptForGamePathAndInitialize(bool isFirstAttempt)
{
    qCDebug(mainWindowLog) << "promptForGamePathAndInitialize called. isFirstAttempt:" << isFirstAttempt;
    QString title = isFirstAttempt ? tr("Укажите путь к папке игры World of Warcraft")
                                   : tr("Не удалось загрузить MPQ. Укажите другой путь к папке игры World of Warcraft");

    QString dir = QFileDialog::getExistingDirectory(this, title, QDir::homePath());

    if (!dir.isEmpty())
    {
        qCInfo(mainWindowLog) << "User selected game path:" << dir;
        m_statusBar->showMessage(tr("Попытка загрузки MPQ из: %1... (может занять время)").arg(dir));

        // Запускаем инициализацию асинхронно с новым путем
        QFuture<QPair<MpqManager*, QString>> future = QtConcurrent::run([dir, this]() { // Захватываем this для логгера
            qCDebug(mainWindowLog) << "QtConcurrent: Starting MpqManager initialization for (user selected)" << dir;
            MpqManager* manager = new MpqManager(dir); // <-- Передаем путь в конструктор
            if (manager->initialize()) { // <-- Вызываем initialize() без аргументов
                qCDebug(mainWindowLog) << "QtConcurrent: MpqManager initialized successfully for" << dir;
                return qMakePair(manager, dir);
            } else {
                qCWarning(mainWindowLog) << "QtConcurrent: Failed to initialize MpqManager for" << dir;
                delete manager;
                return qMakePair(static_cast<MpqManager*>(nullptr), dir);
            }
        });
        m_mpqWatcher->setFuture(future);
    }
    else
    {
        qCWarning(mainWindowLog) << "User did not select a game path.";
        m_statusBar->showMessage(tr("Путь к игре не указан. MPQ не загружены."), 5000);
        if (isFirstAttempt)
        {
            QMessageBox::critical(this, tr("MPQ не загружены"),
                                  tr("Необходимо указать путь к папке World of Warcraft для работы с MPQ архивами. "
                                     "Попробуйте снова через меню Файл -> Указать путь к WoW."));
        }
    }
}

void MainWindow::initializeMapDataManager()
{
    if (m_mpqManager && m_mpqManager->isInitialized())
    {
        qCDebug(mainWindowLog) << "Initializing MapDataManager...";
        // ... (остальная часть функции без изменений)
    }
}

void MainWindow::on_actionSelectWoWPath_triggered()
{
    promptForGamePathAndInitialize(false);  // false - это не первая автоматическая попытка
}