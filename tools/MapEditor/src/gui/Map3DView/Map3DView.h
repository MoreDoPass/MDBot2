#ifndef MAP3DVIEW_H
#define MAP3DVIEW_H

#include <QOpenGLWidget>
#include <QOpenGLFunctions>
#include <QOpenGLShaderProgram>
#include <QOpenGLBuffer>
#include <QOpenGLVertexArrayObject>
#include <QTimer>
#include <QMatrix4x4>
#include <QVector3D>
#include <QSet>
#include <QList>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QDateTime>

// Обязательно для логирования!
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(map3DViewLog)

#include "Camera/Camera.h"
#include "core/MapData/Waypoint.h"  // Вот наш основной Waypoint
#include "core/MapData/MapData.h"   // <--- Добавлено для Obstacle

// Включаем наш новый рендерер
#include "Renderers/WaypointRenderer.h"
#include "Renderers/ConnectionLineRenderer.h"
#include "Renderers/ObstacleRenderer.h"
#include "Renderers/PlayerMarkerRenderer.h"
#include "Renderers/ObstaclePointRenderer.h"
#include "Renderers/ObstacleLineRenderer.h"

/**
 * @brief Основной виджет для отображения 3D-сцены редактора карт.
 *
 * Map3DView наследуется от QOpenGLWidget и использует QOpenGLFunctions для работы с OpenGL.
 * Он отвечает за инициализацию OpenGL, управление камерой (через класс Camera),
 * обработку пользовательского ввода для навигации и взаимодействия, а также
 * координацию отрисовки различных элементов сцены с помощью специализированных
 * классов-рендереров (из директории Renderers/).
 */
class Map3DView : public QOpenGLWidget, protected QOpenGLFunctions
{
    Q_OBJECT

   public:
    /**
     * @brief Конструктор Map3DView.
     * @param parent Родительский виджет.
     */
    explicit Map3DView(QWidget *parent = nullptr);
    /**
     * @brief Деструктор Map3DView. Освобождает ресурсы OpenGL.
     */
    ~Map3DView() override;

    /**
     * @brief Задает список вейпоинтов для отображения.
     * @param waypoints Список объектов Waypoint.
     */
    void setWaypoints(const QList<Waypoint> &waypoints);
    /**
     * @brief Задает список препятствий для отображения.
     * @param obstacles Список объектов Obstacle.
     */
    void setObstacles(const QList<Obstacle> &obstacles);
    /**
     * @brief Очищает все отображаемые данные на карте (вейпоинты, препятствия и т.д.).
     */
    void clearMapDisplayData();

    /**
     * @brief Обновляет позицию маркера игрока на сцене.
     * @param playerPosition Позиция игрока в координатах WoW.
     */
    void updatePlayerPosition(const QVector3D &playerPosition);
    /**
     * @brief Фокусирует камеру на указанной позиции игрока.
     * @param playerPositionInWowCoords Позиция игрока в координатах WoW.
     */
    void focusOnPlayer(const QVector3D &playerPositionInWowCoords);

    /**
     * @brief Добавляет точку для создания нового препятствия на текущей позиции игрока.
     * Используется при активном режиме создания препятствий (например, по нажатию F2).
     * @param wowPlayerPos Позиция игрока в координатах WoW.
     */
    void addObstaclePointAtPlayerPosition(const QVector3D &wowPlayerPos);

    // Методы для управления визуализацией BugPathfinder теста
    void setBugTestMarkers(const QVector3D &start, const QVector3D &goal);
    void setBugPath(const QList<QVector3D> &path);
    void setCurrentBugPosition(const QVector3D &position);
    void setBugHitPoint(const QVector3D &hitPoint);
    void setBugMLine(const QVector3D &start, const QVector3D &goal);
    void clearBugTestData();

    // Статические константы для ID маркеров Bug теста
    // static const int BUG_TEST_START_ID = -1001;
    // static const int BUG_TEST_GOAL_ID = -1002;
    // static const int BUG_TEST_CURR_ID = -1003;
    // static const int BUG_TEST_HIT_ID = -1004;

   protected:
    /**
     * @brief Инициализирует OpenGL, шейдеры и другие ресурсы, необходимые для рендеринга.
     * Вызывается один раз после создания контекста OpenGL.
     * Также инициализирует все дочерние рендереры.
     */
    void initializeGL() override;
    /**
     * @brief Обрабатывает изменение размера виджета. Обновляет viewport и матрицу проекции камеры.
     * @param w Новая ширина виджета.
     * @param h Новая высота виджета.
     */
    void resizeGL(int w, int h) override;
    /**
     * @brief Выполняет отрисовку одного кадра.
     * Очищает экран и вызывает методы render() у всех активных рендереров.
     */
    void paintGL() override;

    // Обработка событий клавиатуры и мыши для камеры
    /**
     * @brief Обрабатывает нажатие клавиши. Используется для управления камерой и других действий.
     * @param event Событие нажатия клавиши.
     */
    void keyPressEvent(QKeyEvent *event) override;
    /**
     * @brief Обрабатывает отпускание клавиши.
     * @param event Событие отпускания клавиши.
     */
    void keyReleaseEvent(QKeyEvent *event) override;
    /**
     * @brief Обрабатывает нажатие кнопки мыши.
     * Используется для выбора объектов, начала вращения камеры или создания точек препятствий.
     * @param event Событие нажатия кнопки мыши.
     */
    void mousePressEvent(QMouseEvent *event) override;
    /**
     * @brief Обрабатывает движение мыши.
     * Используется для вращения камеры (если кнопка зажата) или для отрисовки "резиновой" линии при создании
     * препятствия.
     * @param event Событие движения мыши.
     */
    void mouseMoveEvent(QMouseEvent *event) override;
    /**
     * @brief Обрабатывает прокрутку колеса мыши. Используется для изменения FOV камеры (зум).
     * @param event Событие колеса мыши.
     */
    void wheelEvent(QWheelEvent *event) override;  // Для зума
    /**
     * @brief Обрабатывает отпускание кнопки мыши.
     * Может завершать перетаскивание или генерировать сигнал mapClicked.
     * @param event Событие отпускания кнопки мыши.
     */
    void mouseReleaseEvent(QMouseEvent *event) override;

   signals:
    /**
     * @brief Сигнал, испускаемый при изменении вейпоинтов (например, изменение связей).
     * @param waypoints Обновленный список вейпоинтов.
     */
    void waypointsChanged(const QList<Waypoint> &waypoints);
    /**
     * @brief Сигнал, испускаемый при создании нового полигонального препятствия.
     * @param newObstacle Созданный объект Obstacle.
     */
    void newObstacleCreated(Obstacle newObstacle);
    /**
     * @brief Сигнал, испускаемый при клике на карту (не на существующий объект типа вейпоинта).
     * @param position Мировые координаты точки клика (на плоскости Y=0).
     * @param button Нажатая кнопка мыши.
     */
    void mapClicked(const QVector3D &position, Qt::MouseButton button);

   private slots:
    /**
     * @brief Слот, вызываемый таймером для обновления логики сцены (например, движение камеры) и перерисовки.
     */
    void animate();

   private:
    /**
     * @brief Преобразует 2D координаты точки на экране в 3D мировые координаты.
     * Проецирует точку на плоскость Y=0 в мировой системе координат.
     * @param screenPos Координаты точки на экране (в пикселях).
     * @return QVector3D Мировые координаты точки или нулевой вектор при ошибке.
     */
    QVector3D unprojectScreenToWorld(const QPoint &screenPos);

    QTimer m_timer;
    float m_deltaTime = 0.0f;
    qint64 m_lastFrameTime = 0;

    QPoint m_lastMousePos;
    bool m_mouseDragging = false;

    QSet<int> m_pressedKeys;
    bool m_altKeyPressed = false;

    Camera m_camera;

    // Данные для отображения игрока
    QVector3D m_playerPosition;
    bool m_hasPlayerPosition = false;
    QVector3D m_playerPositionInOpenGLCoords;

    QList<Obstacle> m_displayedObstacles;  // <--- Новый список для хранения препятствий

    int m_selectedWaypointId = -1;  // ID выбранного вейпоинта, -1 если ничего не выбрано

    QList<QVector3D> m_currentObstaclePoints;                   // Точки текущего создаваемого препятствия
    QList<QPair<QVector3D, QVector3D>> m_currentObstacleLines;  // Для отрисовки линий создаваемого препятствия
    QPoint m_currentMouseScreenPos;                             // Для "резиновой" линии до курсора

    QList<Waypoint> m_displayedWaypoints;  // ВОССТАНОВИТЬ/ПРОВЕРИТЬ НАЛИЧИЕ

    WaypointRenderer *m_waypointRenderer;
    ConnectionLineRenderer *m_connectionLineRenderer;
    ObstacleRenderer *m_obstacleRenderer = nullptr;
    PlayerMarkerRenderer *m_playerMarkerRenderer = nullptr;
    ObstaclePointRenderer *m_obstaclePointRenderer = nullptr;
    ObstacleLineRenderer *m_obstacleLineRenderer = nullptr;

    /**
     * @brief Инициализирует все рендереры. Вызывается из initializeGL().
     * @deprecated Заменено прямой инициализацией в initializeGL
     */
    void initializeRenderers();
    /**
     * @brief Освобождает ресурсы всех рендереров. Вызывается из деструктора.
     * @deprecated Заменено прямой очисткой в деструкторе
     */
    void cleanupRenderers();
};

#endif  // MAP3DVIEW_H