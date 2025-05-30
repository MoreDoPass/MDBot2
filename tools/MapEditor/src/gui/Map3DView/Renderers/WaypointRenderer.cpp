#include "WaypointRenderer.h"
#include <QOpenGLFunctions>  // Для доступа к функциям OpenGL и для m_glFuncs
#include <QDebug>            // Для логирования

// Определение категории логирования
Q_LOGGING_CATEGORY(waypointRendererLog, "qt.mapeditor.waypointrenderer")

WaypointRenderer::WaypointRenderer()
    : m_glFuncs(nullptr), m_program(nullptr), m_initialized(false), m_numWaypointsToRender(0)
{
    qCDebug(waypointRendererLog) << "WaypointRenderer constructor called";
}

WaypointRenderer::~WaypointRenderer()
{
    qCDebug(waypointRendererLog) << "WaypointRenderer destructor called";
    // cleanup() будет вызван из Map3DView перед delete,
    // но на всякий случай, если объект уничтожается иначе:
    if (m_initialized)
    {
        cleanup();  // Убедимся, что ресурсы освобождены
    }
}

void WaypointRenderer::initialize(QOpenGLFunctions* functions)
{
    if (!functions)
    {
        qCCritical(waypointRendererLog) << "initialize: QOpenGLFunctions instance is null!";
        return;
    }
    m_glFuncs = functions;  // Сохраняем указатель
    // m_glFuncs->initializeOpenGLFunctions(); // Не нужно, т.к. functions уже инициализирован в Map3DView

    qCDebug(waypointRendererLog) << "Initializing WaypointRenderer...";

    m_program = new QOpenGLShaderProgram();

    // Компиляция вершинного шейдера
    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Vertex, waypoint_vshader_source))
    {
        qCCritical(waypointRendererLog) << "Vertex shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }

    // Компиляция фрагментного шейдера
    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Fragment, waypoint_fshader_source))
    {
        qCCritical(waypointRendererLog) << "Fragment shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }

    // Линковка шейдерной программы
    if (!m_program->link())
    {
        qCCritical(waypointRendererLog) << "Shader program linking failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    qCDebug(waypointRendererLog) << "Waypoint shaders compiled and linked successfully.";

    // Создание VAO и VBO
    m_vao.create();
    m_vbo.create();
    m_vbo.setUsagePattern(QOpenGLBuffer::DynamicDraw);  // Данные будут часто меняться

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    m_vbo.bind();  // Биндим VBO для настройки атрибутов

    // Настройка атрибутов вершин
    // Атрибут 0: Позиция (3 float)
    m_program->enableAttributeArray(0);
    m_program->setAttributeBuffer(0, GL_FLOAT, 0, 3, 6 * sizeof(GLfloat));  // stride = 6 floats

    // Атрибут 1: Цвет (3 float, смещение 3 float от начала вершины)
    m_program->enableAttributeArray(1);
    m_program->setAttributeBuffer(1, GL_FLOAT, 3 * sizeof(GLfloat), 3, 6 * sizeof(GLfloat));  // stride = 6 floats

    m_vbo.release();  // VBO отвязывается, но остается в VAO
    // vaoBinder сам отвяжет VAO в деструкторе

    qCDebug(waypointRendererLog) << "VAO and VBO created, attributes configured.";
    m_initialized = true;
}

void WaypointRenderer::updateData(const QList<Waypoint>& waypoints, int selectedWaypointId)
{
    if (!m_initialized)
    {
        qCWarning(waypointRendererLog) << "updateData called before initialization.";
        return;
    }

    qCDebug(waypointRendererLog) << "Updating data for" << waypoints.size()
                                 << "waypoints. Selected ID:" << selectedWaypointId;

    QVector<GLfloat> waypointVertexData;
    waypointVertexData.reserve(waypoints.size() * 6);  // 6 floats per waypoint (X,Y,Z, R,G,B)

    for (const Waypoint& wp : waypoints)
    {
        // Координаты (X инвертирован для OpenGL)
        waypointVertexData.append(-wp.coordinates.x());
        waypointVertexData.append(wp.coordinates.z());  // WoW Z -> OGL Y
        waypointVertexData.append(wp.coordinates.y());  // WoW Y -> OGL Z

        // Цвет
        bool isSelected = (wp.id == selectedWaypointId);
        const QColor& colorToUse = isSelected ? m_selectedColor : m_normalColor;
        waypointVertexData.append(static_cast<GLfloat>(colorToUse.redF()));
        waypointVertexData.append(static_cast<GLfloat>(colorToUse.greenF()));
        waypointVertexData.append(static_cast<GLfloat>(colorToUse.blueF()));
    }

    m_numWaypointsToRender = waypoints.size();

    if (m_numWaypointsToRender > 0)
    {
        m_vbo.bind();
        m_vbo.allocate(waypointVertexData.constData(), waypointVertexData.size() * sizeof(GLfloat));
        m_vbo.release();
        qCDebug(waypointRendererLog) << "VBO updated with" << m_numWaypointsToRender << "waypoints.";
    }
    else
    {
        // Если нет точек, можно очистить VBO
        m_vbo.bind();
        m_vbo.allocate(nullptr, 0);
        m_vbo.release();
        qCDebug(waypointRendererLog) << "No waypoints to render, VBO cleared.";
    }
}

void WaypointRenderer::render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix)
{
    if (!m_initialized || m_numWaypointsToRender == 0 || !m_program || !m_program->isLinked())
    {
        // qCDebug(waypointRendererLog) << "Render call skipped. Initialized:" << m_initialized
        //                              << "Count:" << m_numWaypointsToRender
        //                              << "Program:" << (m_program ? m_program->isLinked() : false);
        return;
    }

    // qCDebug(waypointRendererLog) << "Rendering" << m_numWaypointsToRender << "waypoints.";

    m_program->bind();
    m_program->setUniformValue("view", viewMatrix);
    m_program->setUniformValue("projection", projectionMatrix);

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);

    // Включаем возможность изменять размер точек в шейдере
    // Это должно быть сделано до вызова glDrawArrays для GL_POINTS
    if (m_glFuncs)
    {  // Убедимся, что m_glFuncs не null
        m_glFuncs->glEnable(GL_PROGRAM_POINT_SIZE);
        // glEnable(GL_POINT_SMOOTH); // Можно включить для сглаживания, если поддерживается
    }

    m_glFuncs->glDrawArrays(GL_POINTS, 0, m_numWaypointsToRender);

    if (m_glFuncs)
    {
        m_glFuncs->glDisable(GL_PROGRAM_POINT_SIZE);
    }

    m_program->release();
}

void WaypointRenderer::cleanup()
{
    qCDebug(waypointRendererLog) << "Cleaning up WaypointRenderer resources...";
    if (!m_initialized) return;  // Если не было инициализации, нечего чистить

    // Уничтожаем VAO и VBO
    // VAO должен быть уничтожен до VBO, если VBO все еще привязан к нему неявно,
    // но QOpenGLVertexArrayObject::Binder должен корректно отвязать VAO при выходе из области видимости,
    // а QOpenGLBuffer::destroy() сама отвязывает буфер, если он был привязан.
    // Для надежности, можно сначала отвязать все, но Qt классы должны справляться.
    m_vao.destroy();
    m_vbo.destroy();

    // Уничтожаем шейдерную программу
    if (m_program)
    {
        delete m_program;
        m_program = nullptr;
    }
    m_initialized = false;
    m_numWaypointsToRender = 0;
    m_glFuncs = nullptr;  // Обнуляем указатель
    qCDebug(waypointRendererLog) << "WaypointRenderer resources cleaned up.";
}
