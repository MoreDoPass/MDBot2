#include "Map3DView.h"
#include <QDebug>       // Для вывода отладочной информации
#include <QColor>       // Для работы с цветом
#include <QKeyEvent>    // Для обработки клавиатуры
#include <QMouseEvent>  // Для обработки мыши
#include <QtMath>       // Для qDegreesToRadians и других мат. функций
#include <QDateTime>    // Для m_lastFrameTime
#include <QOpenGLShader>
#include <QRandomGenerator>
#include <cmath>  // Для std::isnan, std::isinf

// Включаем наш новый класс Waypoint из MapData
#include "core/MapData/Waypoint.h"

// Определение категории логирования
Q_LOGGING_CATEGORY(map3DViewLog, "qt.mapeditor.map3dview")

Map3DView::Map3DView(QWidget *parent)
    : QOpenGLWidget(parent),
      m_camera(),  // Явный вызов конструктора по умолчанию для камеры
      m_hasPlayerPosition(false),
      m_altKeyPressed(false),
      // Инициализация указателей на рендереры значением nullptr
      m_waypointRenderer(nullptr),
      m_connectionLineRenderer(nullptr),
      m_obstacleRenderer(nullptr),
      m_playerMarkerRenderer(nullptr),
      m_obstaclePointRenderer(nullptr),
      m_obstacleLineRenderer(nullptr)
{
    qCDebug(map3DViewLog) << "Map3DView constructor called";

    // Настройка формата поверхности OpenGL
    QSurfaceFormat format;
    format.setRenderableType(QSurfaceFormat::OpenGL);      // Указываем, что используем OpenGL
    format.setProfile(QSurfaceFormat::CoreProfile);        // Используем Core Profile OpenGL
    format.setVersion(3, 3);                               // Запрашиваем OpenGL версии 3.3
    format.setSwapBehavior(QSurfaceFormat::DoubleBuffer);  // Включаем двойную буферизацию
    format.setSwapInterval(1);  // Включаем VSync (синхронизация с частотой обновления экрана)
    setFormat(format);

    setFocusPolicy(Qt::StrongFocus);  // Важно для получения событий клавиатуры виджетом

    // Подключение таймера для вызова слота animate
    connect(&m_timer, &QTimer::timeout, this, &Map3DView::animate);
    m_timer.start(16);  // Целевая частота обновления ~60 FPS (1000ms / 16ms ~= 62.5 FPS)
    m_lastFrameTime = QDateTime::currentMSecsSinceEpoch();  // Инициализация времени последнего кадра

    // Создание экземпляров рендереров
    m_waypointRenderer = new WaypointRenderer();
    m_connectionLineRenderer = new ConnectionLineRenderer();
    m_obstacleRenderer = new ObstacleRenderer();
    m_playerMarkerRenderer = new PlayerMarkerRenderer();
    m_obstaclePointRenderer = new ObstaclePointRenderer();
    m_obstacleLineRenderer = new ObstacleLineRenderer();
}

Map3DView::~Map3DView()
{
    qCDebug(map3DViewLog) << "Map3DView destructor called";
    makeCurrent();  // Делаем контекст OpenGL текущим для безопасного освобождения ресурсов

    // Очистка и удаление рендереров
    if (m_waypointRenderer)
    {
        m_waypointRenderer->cleanup();
        delete m_waypointRenderer;
        m_waypointRenderer = nullptr;
    }

    if (m_connectionLineRenderer)
    {
        m_connectionLineRenderer->cleanup();
        delete m_connectionLineRenderer;
        m_connectionLineRenderer = nullptr;
    }

    if (m_obstacleRenderer)
    {
        m_obstacleRenderer->cleanup();
        delete m_obstacleRenderer;
        m_obstacleRenderer = nullptr;
    }

    if (m_playerMarkerRenderer)
    {
        m_playerMarkerRenderer->cleanup();
        delete m_playerMarkerRenderer;
        m_playerMarkerRenderer = nullptr;
    }

    if (m_obstaclePointRenderer)
    {
        m_obstaclePointRenderer->cleanup();
        delete m_obstaclePointRenderer;
        m_obstaclePointRenderer = nullptr;
    }

    if (m_obstacleLineRenderer)
    {
        m_obstacleLineRenderer->cleanup();
        delete m_obstacleLineRenderer;
        m_obstacleLineRenderer = nullptr;
    }

    qCDebug(map3DViewLog) << "Map3DView OpenGL resources cleaned up.";

    doneCurrent();  // Освобождаем контекст OpenGL
}

void Map3DView::initializeGL()
{
    qCDebug(map3DViewLog) << "Initializing OpenGL...";
    initializeOpenGLFunctions();  // Инициализация QOpenGLFunctions для текущего контекста

    // Установка цвета фона (темно-сине-серый)
    glClearColor(0.1f, 0.1f, 0.2f, 1.0f);

    // Включение теста глубины для корректного отображения 3D объектов
    glEnable(GL_DEPTH_TEST);

    // (Опционально) Включение смешивания для прозрачности, если понадобится
    // glEnable(GL_BLEND);
    // glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    // Включение сглаживания точек и возможности изменять их размер в шейдере
    glEnable(GL_POINT_SMOOTH);  // Может не поддерживаться в Core Profile или требовать glEnable(GL_PROGRAM_POINT_SIZE);
    glEnable(GL_PROGRAM_POINT_SIZE);  // Важно для изменения размера точек в вершинном шейдере

    // Инициализация каждого рендерера
    // Каждый рендерер сам загрузит свои шейдеры, создаст VAO/VBO и настроит атрибуты вершин
    if (m_waypointRenderer)
    {
        m_waypointRenderer->initialize(this);  // 'this' передается как QOpenGLFunctions
    }
    if (m_connectionLineRenderer)
    {
        m_connectionLineRenderer->initialize(this);
    }
    if (m_obstacleRenderer)
    {
        m_obstacleRenderer->initialize(this);
    }
    if (m_playerMarkerRenderer)
    {
        m_playerMarkerRenderer->initialize(this);
    }
    if (m_obstaclePointRenderer)
    {
        m_obstaclePointRenderer->initialize(this);
    }
    if (m_obstacleLineRenderer)
    {
        m_obstacleLineRenderer->initialize(this);
    }

    // Начальная настройка камеры
    m_camera.setPosition(QVector3D(0, 20, 150));  // Начальная позиция камеры

    // Настройка ориентации камеры, чтобы она смотрела на точку (0,0,0)
    QVector3D targetPoint(0.0f, 0.0f, 0.0f);
    QVector3D cameraPos = m_camera.getPosition();
    QVector3D direction = (targetPoint - cameraPos).normalized();  // Вектор направления от камеры к цели

    // Расчет углов рыскания (yaw) и тангажа (pitch)
    // Yaw - вращение вокруг вертикальной оси (Y в нашем случае), Pitch - наклон вверх/вниз
    float yaw_rad = qAtan2(direction.z(), direction.x());  // Угол в плоскости XZ
    float pitch_rad = qAsin(direction.y());                // Угол относительно горизонтальной плоскости

    float yaw_deg = qRadiansToDegrees(yaw_rad);
    float pitch_deg = qRadiansToDegrees(pitch_rad);

    m_camera.setYawPitch(yaw_deg, pitch_deg);  // Устанавливаем рассчитанные углы для камеры
    // m_camera.updateCameraVectors(); // вызовется внутри setYawPitch

    qCDebug(map3DViewLog) << "OpenGL initialized. Camera Pos:" << cameraPos << "Target:" << targetPoint
                          << "Calculated Direction:" << direction << "Yaw:" << yaw_deg << "Pitch:" << pitch_deg;
}

void Map3DView::resizeGL(int w, int h)
{
    qCDebug(map3DViewLog) << "resizeGL called with width:" << w << "height:" << h;
    if (h == 0) h = 1;  // Предотвращение деления на ноль

    glViewport(0, 0, w, h);  // Установка области вывода OpenGL

    // Обновляем матрицу проекции в камере с новым соотношением сторон
    // FOV, aspect ratio, near plane, far plane
    m_camera.setProjection(m_camera.getFov(), static_cast<float>(w) / static_cast<float>(h), 0.1f,
                           10000.0f);  // Используем farPlane из камеры
}

void Map3DView::paintGL()
{
    // Получаем доступ к функциям OpenGL для текущего контекста
    // (хотя мы наследуемся от QOpenGLFunctions, явный вызов иногда может быть полезен или если функции вызываются
    // извне)
    QOpenGLFunctions *f = QOpenGLContext::currentContext()->functions();

    // Очистка буферов цвета и глубины
    f->glClearColor(0.1f, 0.1f, 0.2f, 1.0f);  // Темно-синий фон
    f->glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    // Включение теста глубины (уже было в initializeGL, но можно дублировать для надежности)
    f->glEnable(GL_DEPTH_TEST);
    // f->glEnable(GL_CULL_FACE); // Если нужна отсечка задних граней для оптимизации

    // Получение матриц вида и проекции от камеры
    QMatrix4x4 viewMatrix = m_camera.getViewMatrix();
    // Матрица проекции получается либо из камеры (если она ее хранит и обновляет),
    // либо строится здесь на основе параметров камеры.
    // В данном случае, камера хранит свою матрицу проекции.
    QMatrix4x4 projectionMatrix = m_camera.getProjectionMatrix();

    // Последовательный вызов методов render() для каждого рендерера.
    // Каждый рендерер сам отвечает за активацию своих шейдеров, VAO и отрисовку.

    // 1. Рендеринг основных вейпоинтов
    if (m_waypointRenderer && m_waypointRenderer->isInitialized())
    {
        // updateData для m_waypointRenderer вызывается в setWaypoints или при изменении выделения/связей
        m_waypointRenderer->render(viewMatrix, projectionMatrix);
    }

    // 2. Рендеринг основных соединительных линий между вейпоинтами
    if (m_connectionLineRenderer && m_connectionLineRenderer->isInitialized())
    {
        // updateData для m_connectionLineRenderer вызывается в setWaypoints или при изменении связей
        m_connectionLineRenderer->render(viewMatrix, projectionMatrix);
    }

    // 3. Рендеринг полигональных препятствий
    if (m_obstacleRenderer && m_obstacleRenderer->isInitialized())
    {
        // updateData для m_obstacleRenderer вызывается в setObstacles или при создании нового препятствия
        m_obstacleRenderer->render(viewMatrix, projectionMatrix);
    }

    // 4. Рендеринг маркера игрока
    if (m_hasPlayerPosition && m_playerMarkerRenderer && m_playerMarkerRenderer->isInitialized())
    {
        // PlayerMarkerRenderer::updateData вызывается в updatePlayerPosition,
        // здесь только рендеринг, если маркер видим и инициализирован.
        // m_playerPositionInOpenGLCoords должна быть уже установлена.
        m_playerMarkerRenderer->render(viewMatrix, projectionMatrix);
    }

    // 5. Рендеринг точек и линий текущего создаваемого препятствия (в режиме F2)
    // Сначала точки
    if (m_obstaclePointRenderer && m_obstaclePointRenderer->isInitialized() && !m_currentObstaclePoints.isEmpty())
    {
        // updateData вызывается прямо перед рендерингом, т.к. список точек может меняться каждый кадр
        m_obstaclePointRenderer->updateData(m_currentObstaclePoints);
        m_obstaclePointRenderer->render(viewMatrix, projectionMatrix);
    }
    // Затем линии (включая "резиновую" линию до курсора)
    if (m_obstacleLineRenderer && m_obstacleLineRenderer->isInitialized() && m_currentObstaclePoints.size() >= 1 &&
        !m_currentMouseScreenPos.isNull())  // Нужна хотя бы одна точка для начала линии
    {
        QList<QVector3D> linePoints = m_currentObstaclePoints;
        // Проецируем позицию мыши из экранных координат в мировые для "резиновой" линии
        QVector3D worldMousePos = unprojectScreenToWorld(m_currentMouseScreenPos);
        // Проецируем высоту курсора на высоту последней добавленной точки препятствия
        if (!m_currentObstaclePoints.isEmpty())
        {  // Добавлена проверка
            worldMousePos.setY(m_currentObstaclePoints.last().y());
        }
        else if (m_hasPlayerPosition)
        {  // Если точек нет, но есть игрок, берем его высоту
            worldMousePos.setY(m_playerPositionInOpenGLCoords.y());
        }
        else
        {  // Иначе, просто Y=0
            worldMousePos.setY(0.0f);
        }

        linePoints.append(worldMousePos);  // Добавляем точку курсора для линии

        m_obstacleLineRenderer->updateData(linePoints, worldMousePos);  // Передаем все точки, включая точку курсора
        m_obstacleLineRenderer->render(viewMatrix, projectionMatrix);
    }
}

// Слот, вызываемый таймером для обновления логики и перерисовки
void Map3DView::animate()
{
    qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
    m_deltaTime = (currentTime - m_lastFrameTime) / 1000.0f;  // Время кадра в секундах
    m_lastFrameTime = currentTime;

    // Ограничение deltaTime для предотвращения "прыжков" при больших лагах или при отладке
    if (m_deltaTime > 0.1f)  // Максимум 0.1 секунды (10 FPS)
    {
        m_deltaTime = 0.1f;
    }
    if (m_deltaTime <= 0.0f)  // Минимум, соответствующий ~60 FPS, если dt некорректен
    {
        m_deltaTime = 1.0f / 60.0f;
    }

    qCDebug(map3DViewLog).nospace() << "[Animate] dt: " << QString::asprintf("%.4f", m_deltaTime) << " Keys: ["
                                    << m_pressedKeys << "] CamPos: " << m_camera.getPosition();

    // Обновление состояния камеры на основе нажатых клавиш и deltaTime
    m_camera.processKeyboard(m_pressedKeys, m_deltaTime);
    update();  // Запрос на перерисовку виджета (вызовет paintGL)
}

void Map3DView::keyPressEvent(QKeyEvent *event)
{
    if (event->isAutoRepeat())  // Игнорировать автоповтор клавиш
    {
        event->ignore();
        return;
    }
    m_pressedKeys.insert(event->key());  // Добавляем нажатую клавишу в сет

    // Обработка специфических клавиш
    if (event->key() == Qt::Key_Alt && m_selectedWaypointId != -1)  // Если нажат Alt и есть выделенный вейпоинт
    {
        m_altKeyPressed = true;  // Включаем режим соединения вейпоинтов
        qCDebug(map3DViewLog) << "Alt pressed, connect mode ON for waypoint:" << m_selectedWaypointId;
    }
    else if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter)  // Завершение создания препятствия
    {
        if (!m_currentObstaclePoints.isEmpty() &&
            m_currentObstaclePoints.size() >= 3)  // Нужно минимум 3 точки для полигона
        {
            qCDebug(map3DViewLog) << "Enter pressed, finalizing obstacle creation.";
            // Создаем новый объект Obstacle из текущих точек
            Obstacle newObstacle(m_currentObstaclePoints,
                                 QDateTime::currentMSecsSinceEpoch(),  // Уникальный ID на основе времени
                                 QString("ShapeObstacle_%1").arg(QDateTime::currentMSecsSinceEpoch()));  // Имя

            m_displayedObstacles.append(newObstacle);  // Добавляем в список отображаемых
            emit newObstacleCreated(newObstacle);      // Испускаем сигнал о создании нового препятствия
            qCDebug(map3DViewLog) << "New shape obstacle created with ID:" << newObstacle.id
                                  << "Name:" << newObstacle.name << "Vertices:" << newObstacle.shapeVertices.size()
                                  << "MinCorner:" << newObstacle.minCorner << "MaxCorner:" << newObstacle.maxCorner;

            m_currentObstaclePoints.clear();  // Очищаем текущие точки для следующего препятствия
            if (m_obstacleRenderer)           // Обновляем данные в рендерере препятствий
            {
                m_obstacleRenderer->updateData(m_displayedObstacles);
            }
            update();  // Перерисовываем сцену
        }
        else if (!m_currentObstaclePoints.isEmpty())
        {
            qCDebug(map3DViewLog) << "Enter pressed, but not enough points for obstacle (need >= 3). Current:"
                                  << m_currentObstaclePoints.size();
        }
    }
    else if (event->key() == Qt::Key_Escape)  // Отмена создания текущего препятствия
    {
        if (!m_currentObstaclePoints.isEmpty())
        {
            qCDebug(map3DViewLog) << "Escape pressed, clearing current obstacle points.";
            m_currentObstaclePoints.clear();
            // Также нужно очистить данные в ObstaclePointRenderer и ObstacleLineRenderer, если они их кэшируют.
            // В данном случае, они обновляются каждый кадр в paintGL, так что очистка m_currentObstaclePoints
            // достаточна.
            update();
        }
    }
    // QWidget::keyPressEvent(event); // Можно вызвать базовую реализацию, если нужно стандартное поведение
}

void Map3DView::keyReleaseEvent(QKeyEvent *event)
{
    if (event->isAutoRepeat())
    {  // Игнорируем автоповтор
        event->ignore();
        return;
    }
    m_pressedKeys.remove(event->key());  // Удаляем отпущенную клавишу из сета
    if (event->key() == Qt::Key_Alt)
    {
        m_altKeyPressed = false;  // Выключаем режим соединения, если Alt отпущен
        qCDebug(map3DViewLog) << "Alt key released";
    }
    QWidget::keyReleaseEvent(event);  // Вызов базовой реализации
}

void Map3DView::mousePressEvent(QMouseEvent *event)
{
    m_lastMousePos = event->pos();  // Запоминаем позицию клика для последующего mouseMoveEvent

    qCDebug(map3DViewLog) << "MousePressEvent triggered for button:" << event->button();
    bool connectionChanged = false;     // Флаг: изменились ли связи между вейпоинтами
    bool waypointsDataChanged = false;  // Флаг: изменились ли данные вейпоинтов (например, выделение)

    if (event->button() == Qt::LeftButton)  // Обработка левой кнопки мыши
    {
        // Логика определения ID вейпоинта, по которому кликнули
        int clickedWaypointId = -1;
        float minDepth = std::numeric_limits<float>::max();  // Для выбора ближайшего вейпоинта

        QMatrix4x4 viewMatrix = m_camera.getViewMatrix();
        QMatrix4x4 projMatrix = m_camera.getProjectionMatrix();
        QRect viewportRect(0, 0, width(), height());

        // Параметры для расчета размера точки на экране и области клика
        const float K_SIZE_SCALER = 200.0f;    // Коэффициент для динамического размера точки
        const float MIN_POINT_SIZE = 2.0f;     // Минимальный размер точки в пикселях
        const float MAX_POINT_SIZE = 100.0f;   // Максимальный размер точки
        const float CLICK_SLOP_PIXELS = 5.0f;  // Допуск клика в пикселях (немного увеличил для удобства)

        for (const Waypoint &wp : m_displayedWaypoints)
        {
            // Преобразование координат вейпоинта из WoW в OpenGL
            QVector3D waypointOglPos(-wp.coordinates.x(), wp.coordinates.z(), wp.coordinates.y());

            // Расчет расстояния до камеры для динамического изменения размера точки
            QVector4D viewPos = viewMatrix * QVector4D(waypointOglPos, 1.0f);
            float distanceToCamera = viewPos.length();
            if (distanceToCamera < 0.001f) distanceToCamera = 0.001f;  // Избегаем деления на ноль

            float pointSize = qBound(MIN_POINT_SIZE, K_SIZE_SCALER / distanceToCamera, MAX_POINT_SIZE);

            // Проецирование 3D точки на 2D экран
            QVector3D screenPos = waypointOglPos.project(viewMatrix, projMatrix, viewportRect);
            // Y координата в Qt инвертирована по сравнению с OpenGL NDC
            screenPos.setY(static_cast<float>(viewportRect.height()) - screenPos.y());

            // Отсекаем точки за ближней/дальней плоскостью отсечения
            if (screenPos.z() < 0.0f || screenPos.z() > 1.0f) continue;

            QPointF clickPosQt = event->pos();  // Текущая позиция клика
            float dx = clickPosQt.x() - screenPos.x();
            float dy = clickPosQt.y() - screenPos.y();

            // Проверка, попал ли клик в область точки с учетом допуска
            float effectiveClickableHalfWidth = (pointSize / 2.0f) + CLICK_SLOP_PIXELS;
            if (qAbs(dx) < effectiveClickableHalfWidth && qAbs(dy) < effectiveClickableHalfWidth)
            {
                if (screenPos.z() < minDepth)  // Если этот вейпоинт ближе к камере
                {
                    minDepth = screenPos.z();
                    clickedWaypointId = wp.id;
                }
            }
        }
        qCDebug(map3DViewLog) << "Clicked waypoint ID (after loop):" << clickedWaypointId;

        // Логика соединения/разъединения вейпоинтов при зажатой Alt
        if (m_altKeyPressed && m_selectedWaypointId != -1 && clickedWaypointId != -1 &&
            clickedWaypointId != m_selectedWaypointId)
        {
            qCDebug(map3DViewLog) << "AltConnectMode: Attempting to connect/disconnect WP:" << m_selectedWaypointId
                                  << "with WP:" << clickedWaypointId;
            Waypoint *selectedWP = nullptr;
            Waypoint *targetWP = nullptr;
            // Находим указатели на изменяемые вейпоинты в m_displayedWaypoints
            for (Waypoint &wp_ref : m_displayedWaypoints)
            {
                if (wp_ref.id == m_selectedWaypointId) selectedWP = &wp_ref;
                if (wp_ref.id == clickedWaypointId) targetWP = &wp_ref;
                if (selectedWP && targetWP) break;
            }

            if (selectedWP && targetWP)
            {
                if (selectedWP->connectedWaypointIds.contains(clickedWaypointId))  // Если связь уже есть - удаляем
                {
                    selectedWP->connectedWaypointIds.remove(clickedWaypointId);
                    targetWP->connectedWaypointIds.remove(m_selectedWaypointId);  // Удаляем в обе стороны
                    qCDebug(map3DViewLog)
                        << "Connection removed between WP:" << m_selectedWaypointId << "and WP:" << clickedWaypointId;
                }
                else  // Иначе - добавляем связь
                {
                    selectedWP->connectedWaypointIds.insert(clickedWaypointId);
                    targetWP->connectedWaypointIds.insert(m_selectedWaypointId);  // Добавляем в обе стороны
                    qCDebug(map3DViewLog)
                        << "Connection added between WP:" << m_selectedWaypointId << "and WP:" << clickedWaypointId;
                }
                waypointsDataChanged = true;  // Данные вейпоинтов изменились
                connectionChanged = true;     // Связи изменились
                qCDebug(map3DViewLog) << "Connection changed, flagging for update.";
            }
            m_mouseDragging = false;  // Не вращать камеру при изменении связей
        }
        else if (clickedWaypointId != -1)  // Если кликнули по вейпоинту (не в режиме Alt-соединения)
        {
            // Обычный клик по точке (выделение)
            if (m_selectedWaypointId != clickedWaypointId)  // Если кликнули по новому вейпоинту
            {
                m_selectedWaypointId = clickedWaypointId;
                waypointsDataChanged = true;  // Данные (выделение) изменились
                qCDebug(map3DViewLog) << "Waypoint selected: ID =" << m_selectedWaypointId;
                if (m_altKeyPressed)
                    m_altKeyPressed = false;  // Сбросить Alt, если он был нажат без успешного соединения
            }
            // Опционально: Клик по уже выделенной точке - можно добавить логику снятия выделения
            // else {
            //     m_selectedWaypointId = -1; // Снятие выделения
            //     waypointsDataChanged = true;
            //     qCDebug(map3DViewLog) << "Waypoint deselected: ID =" << clickedWaypointId;
            // }
            m_mouseDragging = false;  // Не вращать камеру, если кликнули по вейпоинту
        }
        else  // Клик мимо всех вейпоинтов
        {
            qCDebug(map3DViewLog) << "Mouse click did not hit any waypoint.";
            if (m_selectedWaypointId != -1 &&
                !m_altKeyPressed)  // Сбрасываем выделение, если не в режиме Alt-соединения
            {
                qCDebug(map3DViewLog) << "Deselecting waypoint:" << m_selectedWaypointId;
                m_selectedWaypointId = -1;
                waypointsDataChanged = true;
            }
            m_mouseDragging = true;  // Разрешаем вращение камеры, если клик был не по точке
        }

        // Если данные вейпоинтов изменились, обновляем их в рендерерах
        if (waypointsDataChanged)
        {
            qCDebug(map3DViewLog) << "[mousePressEvent] Waypoint data changed, updating renderer and view.";
            if (m_waypointRenderer)
            {
                m_waypointRenderer->updateData(m_displayedWaypoints, m_selectedWaypointId);
            }
            if (m_connectionLineRenderer)  // Также обновляем линии, т.к. выделение могло повлиять на их цвет (если есть
                                           // такая логика) или просто для консистентности
            {
                m_connectionLineRenderer->updateData(m_displayedWaypoints);
            }
            update();  // Перерисовываем сцену
        }

        // Если связи изменились, испускаем сигнал
        if (connectionChanged)
        {
            qCDebug(map3DViewLog) << "[mousePressEvent] Emitting waypointsChanged signal.";
            emit waypointsChanged(m_displayedWaypoints);  // Оповещаем внешний мир об изменении связей
        }
    }
    else if (event->button() == Qt::RightButton)  // Правая кнопка мыши
    {
        m_mouseDragging = true;  // Разрешаем вращение/перемещение камеры правой кнопкой
        qCDebug(map3DViewLog) << "Right mouse button pressed, m_mouseDragging = true";
    }
    // QWidget::mousePressEvent(event); // Не вызываем базовый, т.к. полностью переопределяем поведение
}

void Map3DView::mouseMoveEvent(QMouseEvent *event)
{
    // Если мы в процессе создания препятствия, обновляем позицию курсора для "резиновой" линии
    if (!m_currentObstaclePoints.isEmpty())
    {
        m_currentMouseScreenPos = event->pos();  // Сохраняем экранные координаты мыши
        update();                                // Перерисовываем, чтобы видеть линию до курсора
    }

    // Вращение камеры, если зажата левая кнопка мыши и разрешено перетаскивание
    // (m_mouseDragging устанавливается в true, если клик был не по вейпоинту или правой кнопкой)
    if (m_mouseDragging &&
        (event->buttons() & (Qt::LeftButton | Qt::RightButton)))  // Вращение и левой и правой кнопкой
    {
        float xoffset = event->pos().x() - m_lastMousePos.x();  // Смещение по X
        float yoffset =
            m_lastMousePos.y() - event->pos().y();  // Смещение по Y (инвертировано, т.к. Y в Qt растет вниз)
        m_lastMousePos = event->pos();              // Обновляем последнюю позицию мыши

        m_camera.processMouseMovement(xoffset, yoffset);  // Передаем смещение в камеру
        update();                                         // Перерисовываем сцену с новым положением камеры
    }
    else  // Если не вращаем камеру, просто обновляем m_lastMousePos для следующего события
    {
        m_lastMousePos = event->pos();
    }
    QWidget::mouseMoveEvent(event);  // Вызов базовой реализации
}

void Map3DView::mouseReleaseEvent(QMouseEvent *event)
{
    // Если это было перетаскивание (вращение камеры), то просто сбрасываем флаг
    if (m_mouseDragging && (event->button() == Qt::LeftButton || event->button() == Qt::RightButton))
    {
        m_mouseDragging = false;
        event->accept();
        update();
        return;
    }

    // Если это не было перетаскивание, считаем это кликом по карте
    // (например, для создания точки препятствия или другого взаимодействия)
    QVector3D worldPos = unprojectScreenToWorld(event->pos());  // Получаем 3D координаты клика на плоскости Y=0

    // Испускаем сигнал, если позиция валидна (не null)
    if (!worldPos.isNull())
    {
        qCDebug(map3DViewLog) << "Map clicked at screen pos:" << event->pos() << "world pos:" << worldPos
                              << "button:" << event->button();
        emit mapClicked(worldPos, event->button());  // Испускаем сигнал о клике по карте
    }
    else
    {
        qCDebug(map3DViewLog)
            << "Map clicked at screen pos:" << event->pos()
            << "but world position is null (likely click outside defined plane or unprojection error).";
    }

    event->accept();
    update();
}

void Map3DView::wheelEvent(QWheelEvent *event)
{
    QPoint numDegrees = event->angleDelta() / 8;  // Получаем "градусы" прокрутки
    if (!numDegrees.isNull())
    {
        float scrollAmount = static_cast<float>(numDegrees.y());  // Нас интересует вертикальная прокрутка
        qCDebug(map3DViewLog) << "Wheel: deltaY=" << numDegrees.y() << "CamPreFOV:" << m_camera.getFov();
        m_camera.processMouseScroll(scrollAmount / 15.0f);  // Передаем в камеру для изменения FOV (зума)
                                                            // Деление на 15.0f для нормализации скорости зума
        qCDebug(map3DViewLog) << "Wheel: CamPostFOV:" << m_camera.getFov();
    }
    event->accept();
    update();  // Перерисовываем сцену с новым FOV
}

// Обновление позиции игрока и его маркера
void Map3DView::updatePlayerPosition(const QVector3D &playerPosition)  // playerPosition в WoW координатах
{
    qCDebug(map3DViewLog) << "Updating player position. WoW Coords:" << playerPosition;
    m_playerPosition = playerPosition;               // Сохраняем оригинальные WoW координаты
    m_hasPlayerPosition = !playerPosition.isNull();  // Флаг валидности позиции

    // Преобразуем WoW координаты в нашу систему OpenGL для рендеринга
    // OpenGL X = -WoW X
    // OpenGL Y = WoW Z (высота)
    // OpenGL Z = WoW Y (глубина)
    if (m_hasPlayerPosition)
    {
        m_playerPositionInOpenGLCoords = QVector3D(-playerPosition.x(), playerPosition.z(), playerPosition.y());
    }
    else
    {
        m_playerPositionInOpenGLCoords = QVector3D();  // Сбрасываем, если позиция невалидна
    }
    qCDebug(map3DViewLog) << "Player OGL Coords:" << m_playerPositionInOpenGLCoords
                          << "Visible:" << m_hasPlayerPosition;

    // Обновляем данные в рендерере маркера игрока
    if (m_playerMarkerRenderer)
    {
        m_playerMarkerRenderer->updateData(m_playerPositionInOpenGLCoords, m_hasPlayerPosition);
    }

    update();  // Перерисовываем сцену
}

// Фокусировка камеры на игроке
void Map3DView::focusOnPlayer(const QVector3D &playerPositionInWowCoords)
{
    qCDebug(map3DViewLog) << "Focusing on player. WoW Coords:" << playerPositionInWowCoords;

    // Преобразуем WoW координаты цели в OpenGL координаты
    QVector3D targetPositionInScene(-playerPositionInWowCoords.x(), playerPositionInWowCoords.z(),
                                    playerPositionInWowCoords.y());
    qCDebug(map3DViewLog) << "Target OpenGL scene position for camera:" << targetPositionInScene;

    // Устанавливаем позицию камеры немного позади и выше цели
    // Направление взгляда будет на цель
    // Эти значения смещения (offset) можно настроить для лучшего вида
    // Используем фиксированный смещение относительно цели, как было до изменений
    QVector3D cameraOffset(0.0f, -10.0f, -30.0f);  // Смещение назад и немного вверх от цели (в OpenGL координатах)
    QVector3D cameraPosition = targetPositionInScene - cameraOffset;

    m_camera.setPosition(cameraPosition);

    // Направляем камеру на цель
    QVector3D newCamDir = (targetPositionInScene - m_camera.getPosition()).normalized();
    float targetYaw = qRadiansToDegrees(atan2(newCamDir.z(), newCamDir.x()));
    float targetPitch = qRadiansToDegrees(asin(newCamDir.y()));

    qCDebug(map3DViewLog) << "Calculated camera Yaw:" << targetYaw << "Pitch:" << targetPitch;
    m_camera.setYawPitch(targetYaw, targetPitch);

    qCDebug(map3DViewLog) << "Camera position set to:" << m_camera.getPosition() << "Yaw:" << m_camera.getYaw()
                          << "Pitch:" << m_camera.getPitch();
    update();
}

// Установка списка вейпоинтов для отображения
void Map3DView::setWaypoints(const QList<Waypoint> &waypoints)
{
    qCDebug(map3DViewLog) << "[setWaypoints] Called with" << waypoints.size() << "waypoints.";
    m_displayedWaypoints = waypoints;  // Копируем список

    // Обновляем данные в соответствующих рендерерах
    if (m_waypointRenderer)
    {
        m_waypointRenderer->updateData(m_displayedWaypoints, m_selectedWaypointId);
    }
    if (m_connectionLineRenderer)
    {
        m_connectionLineRenderer->updateData(m_displayedWaypoints);
    }
    qCDebug(map3DViewLog) << "[setWaypoints] m_displayedWaypoints.size():" << m_displayedWaypoints.size();
    update();  // Перерисовываем сцену
}

// Установка списка препятствий для отображения
void Map3DView::setObstacles(const QList<Obstacle> &obstacles)
{
    qCDebug(map3DViewLog) << "Setting" << obstacles.size() << "obstacles for display.";
    m_displayedObstacles = obstacles;  // Копируем список

    if (m_obstacleRenderer)  // Обновляем данные в рендерере препятствий
    {
        m_obstacleRenderer->updateData(m_displayedObstacles);
    }
    update();  // Перерисовываем сцену
}

// Очистка всех отображаемых данных
void Map3DView::clearMapDisplayData()
{
    qCDebug(map3DViewLog) << "Clearing all map display data (waypoints, connections, obstacles).";

    m_displayedWaypoints.clear();
    m_selectedWaypointId = -1;  // Сбрасываем выделение

    // Обновляем рендереры пустыми данными
    if (m_waypointRenderer)
    {
        m_waypointRenderer->updateData(m_displayedWaypoints, m_selectedWaypointId);
    }
    if (m_connectionLineRenderer)
    {
        m_connectionLineRenderer->updateData(m_displayedWaypoints);
    }

    m_displayedObstacles.clear();
    if (m_obstacleRenderer)
    {
        m_obstacleRenderer->updateData(m_displayedObstacles);
    }

    m_currentObstaclePoints.clear();  // Очищаем также точки текущего создаваемого препятствия
    // m_currentMouseScreenPos = QPoint(); // Сбрасывать не обязательно, оно обновится при движении мыши

    update();  // Запрашиваем перерисовку, чтобы отобразить пустую карту
}

// Преобразование 2D экранных координат в 3D мировые координаты на плоскости Y=targetY
QVector3D Map3DView::unprojectScreenToWorld(const QPoint &screenPos)
{
    QMatrix4x4 viewMatrix = m_camera.getViewMatrix();
    QMatrix4x4 projectionMatrix = m_camera.getProjectionMatrix();
    QRect viewportRect(0, 0, width(), height());  // Область вывода

    // Координаты OpenGL: Y инвертирован относительно Qt, Z от 0 (ближняя) до 1 (дальняя плоскость)
    float glScreenX = static_cast<float>(screenPos.x());
    float glScreenY = static_cast<float>(height() - screenPos.y());  // Инверсия Y

    // Точки на ближней и дальней плоскостях отсечения в Normalized Device Coordinates (NDC)
    // QVector3D::unproject ожидает Z в диапазоне [0, 1] для Qt
    QVector3D nearNdc(glScreenX, glScreenY, 0.0f);  // z = 0 для ближней плоскости
    QVector3D farNdc(glScreenX, glScreenY, 1.0f);   // z = 1 для дальней плоскости

    // Выполняем обратное проецирование (unproject)
    QVector3D nearWorld = nearNdc.unproject(viewMatrix, projectionMatrix, viewportRect);
    QVector3D farWorld = farNdc.unproject(viewMatrix, projectionMatrix, viewportRect);

    // Проверка на ошибки unproject (NaN/Inf)
    if (std::isnan(nearWorld.x()) || std::isnan(nearWorld.y()) || std::isnan(nearWorld.z()) ||
        std::isinf(nearWorld.x()) || std::isinf(nearWorld.y()) || std::isinf(nearWorld.z()) ||
        std::isnan(farWorld.x()) || std::isnan(farWorld.y()) || std::isnan(farWorld.z()) || std::isinf(farWorld.x()) ||
        std::isinf(farWorld.y()) || std::isinf(farWorld.z()))
    {
        qCWarning(map3DViewLog) << "Unprojected coordinates are NaN or Inf. ScreenPos:" << screenPos;
        return QVector3D();  // Возвращаем нулевой (невалидный) вектор
    }

    // Теперь у нас есть луч, исходящий из nearWorld в направлении (farWorld - nearWorld)
    QVector3D rayOrigin = nearWorld;
    QVector3D rayDirection = (farWorld - nearWorld).normalized();

    // Мы хотим найти пересечение этого луча с горизонтальной плоскостью Y = targetY
    // Для простоты, будем считать targetY равным высоте последней добавленной точки препятствия,
    // или высоте игрока, или 0, если ничего из этого нет.
    float targetY = 0.0f;
    if (!m_currentObstaclePoints.isEmpty())
    {
        targetY = m_currentObstaclePoints.last().y();
    }
    else if (m_hasPlayerPosition)
    {
        targetY = m_playerPositionInOpenGLCoords.y();
    }

    // Если луч параллелен плоскости Y (т.е. его Y-компонента направления близка к 0)
    if (qAbs(rayDirection.y()) < 1e-6)
    {
        // Если камера (начало луча) уже на этой плоскости, то любая точка луча на ней.
        // Это маловероятный и сложный для однозначной обработки случай.
        if (qAbs(rayOrigin.y() - targetY) < 1e-6)
        {
            qCDebug(map3DViewLog) << "Ray is parallel to target Y-plane and origin is on it. Returning ray origin.";
            return rayOrigin;
        }
        qCWarning(map3DViewLog) << "Ray is parallel to target Y-plane. No unique intersection point. RayDir.Y:"
                                << rayDirection.y();
        return QVector3D();  // Не можем найти точку пересечения
    }

    // Вычисляем параметр t для пересечения луча (P = P0 + t*V) с плоскостью (Y = targetY)
    // P0.y + t*V.y = targetY  => t = (targetY - P0.y) / V.y
    float t = (targetY - rayOrigin.y()) / rayDirection.y();

    // Точка пересечения
    QVector3D intersectionPoint = rayOrigin + t * rayDirection;

    qCDebug(map3DViewLog) << "unprojectScreenToWorld: screenPos" << screenPos << "-> rayOrigin:" << rayOrigin
                          << "rayDir:" << rayDirection << "targetY:" << targetY << "t:" << t
                          << "-> worldPos:" << intersectionPoint;
    return intersectionPoint;
}

// Добавление точки для нового препятствия на позиции игрока
void Map3DView::addObstaclePointAtPlayerPosition(const QVector3D &wowPlayerPos)
{
    // Проверка, что есть валидная позиция игрока
    if (wowPlayerPos.isNull())
    {
        qCWarning(map3DViewLog) << "Attempted to add obstacle point with null player position.";
        return;
    }

    // Преобразуем WoW координаты в нашу систему OpenGL
    // OpenGL X = -WoW X
    // OpenGL Y = WoW Z (высота игрока в мире)
    // OpenGL Z = WoW Y (глубина игрока в мире)
    QVector3D obstacleVertex(-wowPlayerPos.x(), wowPlayerPos.z(), wowPlayerPos.y());

    m_currentObstaclePoints.append(obstacleVertex);  // Добавляем точку в список
    qCDebug(map3DViewLog) << "Added obstacle point at player's 3D position (WoW:" << wowPlayerPos
                          << ", OGL:" << obstacleVertex << "). Total points:" << m_currentObstaclePoints.size();

    // Обновляем рендереры точек и линий препятствия
    if (m_obstaclePointRenderer)
    {
        m_obstaclePointRenderer->updateData(m_currentObstaclePoints);
    }
    // Для ObstacleLineRenderer данные обновляются в paintGL, но можно и здесь, если m_currentMouseScreenPos известно
    // или если не нужна "резиновая" линия от последней добавленной точки до курсора в этот момент.

    update();  // Перерисовываем сцену, чтобы показать новую точку и, возможно, линию
}

// Методы для управления визуализацией BugPathfinder теста
void Map3DView::setBugTestMarkers(const QVector3D &start, const QVector3D &goal)
{
    qCDebug(map3DViewLog) << "setBugTestMarkers: Start:" << start << "Goal:" << goal;
    // TODO: Реализовать отображение маркеров начала и цели для Bug теста
    // Можно использовать WaypointRenderer с специальными ID или отдельный маркер-рендерер
    update();
}

void Map3DView::setBugPath(const QList<QVector3D> &path)
{
    qCDebug(map3DViewLog) << "setBugPath: Path size:" << path.size();
    // TODO: Реализовать отображение пути Bug алгоритма (список линий)
    // Можно использовать ConnectionLineRenderer или отдельный рендерер для пути
    update();
}

void Map3DView::setCurrentBugPosition(const QVector3D &position)
{
    qCDebug(map3DViewLog) << "setCurrentBugPosition: Position:" << position;
    // TODO: Реализовать отображение текущей позиции агента Bug алгоритма
    // Можно использовать WaypointRenderer с специальным ID или отдельный маркер-рендерер
    update();
}

void Map3DView::setBugHitPoint(const QVector3D &hitPoint)
{
    qCDebug(map3DViewLog) << "setBugHitPoint: HitPoint:" << hitPoint;
    // TODO: Реализовать отображение точки столкновения Bug алгоритма
    // Можно использовать WaypointRenderer с специальным ID или отдельный маркер-рендерер
    update();
}

void Map3DView::setBugMLine(const QVector3D &start, const QVector3D &goal)
{
    qCDebug(map3DViewLog) << "setBugMLine: Start:" << start << "Goal:" << goal;
    // TODO: Реализовать отображение M-Line (линия от старта к цели)
    // Можно использовать ConnectionLineRenderer или отдельный рендерер
    update();
}

void Map3DView::clearBugTestData()
{
    qCDebug(map3DViewLog) << "clearBugTestData called.";
    // TODO: Реализовать очистку всех визуальных элементов, связанных с Bug тестом
    update();
}

// Методы initializeRenderers() и cleanupRenderers() можно удалить,
// если вся их логика перенесена напрямую в initializeGL() и деструктор ~Map3DView() соответственно.
// Судя по коду, они не вызываются и их можно безопасно удалить.
void Map3DView::initializeRenderers()
{ /* Эта логика теперь в initializeGL */
}
void Map3DView::cleanupRenderers()
{ /* Эта логика теперь в ~Map3DView */
}