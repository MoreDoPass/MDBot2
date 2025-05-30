#include "ConnectionLineRenderer.h"
#include <QOpenGLFunctions>
#include <QDebug>
#include <QMap>  // Для удобного поиска позиций вейпоинтов по ID

// Определение категории логирования
Q_LOGGING_CATEGORY(connectionLineRendererLog, "qt.mapeditor.connectionlinerenderer")

ConnectionLineRenderer::ConnectionLineRenderer()
    : m_glFuncs(nullptr), m_program(nullptr), m_initialized(false), m_numVerticesToRender(0)
{
    qCDebug(connectionLineRendererLog) << "ConnectionLineRenderer constructor called";
}

ConnectionLineRenderer::~ConnectionLineRenderer()
{
    qCDebug(connectionLineRendererLog) << "ConnectionLineRenderer destructor called";
    if (m_initialized)
    {
        cleanup();
    }
}

void ConnectionLineRenderer::initialize(QOpenGLFunctions* functions)
{
    if (!functions)
    {
        qCCritical(connectionLineRendererLog) << "initialize: QOpenGLFunctions instance is null!";
        return;
    }
    m_glFuncs = functions;
    qCDebug(connectionLineRendererLog) << "Initializing ConnectionLineRenderer...";

    m_program = new QOpenGLShaderProgram();

    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Vertex, line_vshader_source))
    {
        qCCritical(connectionLineRendererLog) << "Vertex shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Fragment, line_fshader_source))
    {
        qCCritical(connectionLineRendererLog) << "Fragment shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->link())
    {
        qCCritical(connectionLineRendererLog) << "Shader program linking failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    qCDebug(connectionLineRendererLog) << "Line shaders compiled and linked successfully.";

    m_vao.create();
    m_vbo.create();
    m_vbo.setUsagePattern(QOpenGLBuffer::DynamicDraw);

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    m_vbo.bind();

    m_program->enableAttributeArray(0);                                     // aPos
    m_program->setAttributeBuffer(0, GL_FLOAT, 0, 3, 3 * sizeof(GLfloat));  // X,Y,Z, stride = 3 floats

    m_vbo.release();
    qCDebug(connectionLineRendererLog) << "VAO and VBO created, attributes configured.";
    m_initialized = true;
}

void ConnectionLineRenderer::updateData(const QList<Waypoint>& waypoints)
{
    if (!m_initialized)
    {
        qCWarning(connectionLineRendererLog) << "updateData called before initialization.";
        return;
    }

    qCDebug(connectionLineRendererLog) << "Updating connection line data for" << waypoints.size() << "waypoints.";

    QVector<GLfloat> lineVertexData;
    // Резервируем место. Каждая связь - 2 вершины, каждая вершина - 3 float.
    // В худшем случае (полный граф) N*(N-1)/2 связей. Максимум N*N*3 float.
    // Это грубая оценка, но лучше, чем ничего.
    lineVertexData.reserve(waypoints.size() * waypoints.size() * 3);

    QMap<int, QVector3D> waypointPositionsOgl;
    for (const Waypoint& wp : waypoints)
    {
        waypointPositionsOgl[wp.id] = QVector3D(-wp.coordinates.x(), wp.coordinates.z(), wp.coordinates.y());
    }

    for (const Waypoint& wpA : waypoints)
    {
        if (!waypointPositionsOgl.contains(wpA.id)) continue;
        QVector3D posA = waypointPositionsOgl.value(wpA.id);

        for (int connectedIdB : wpA.connectedWaypointIds)
        {
            // Чтобы избежать дублирования линий (A-B и B-A) и петель (A-A),
            // рисуем линию только если ID текущей точки меньше ID связанной точки.
            if (wpA.id < connectedIdB && waypointPositionsOgl.contains(connectedIdB))
            {
                QVector3D posB = waypointPositionsOgl.value(connectedIdB);

                lineVertexData.append(posA.x());
                lineVertexData.append(posA.y());
                lineVertexData.append(posA.z());

                lineVertexData.append(posB.x());
                lineVertexData.append(posB.y());
                lineVertexData.append(posB.z());
            }
        }
    }

    m_numVerticesToRender = lineVertexData.size() / 3;  // Количество вершин, не линий

    if (m_numVerticesToRender > 0)
    {
        m_vbo.bind();
        m_vbo.allocate(lineVertexData.constData(), lineVertexData.size() * sizeof(GLfloat));
        m_vbo.release();
        qCDebug(connectionLineRendererLog)
            << "VBO updated with" << m_numVerticesToRender << "vertices for connection lines.";
    }
    else
    {
        m_vbo.bind();
        m_vbo.allocate(nullptr, 0);  // Очищаем VBO, если нет линий
        m_vbo.release();
        qCDebug(connectionLineRendererLog) << "No connection lines to render, VBO cleared.";
    }
}

void ConnectionLineRenderer::render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix)
{
    if (!m_initialized || m_numVerticesToRender == 0 || !m_program || !m_program->isLinked())
    {
        return;
    }

    m_program->bind();
    m_program->setUniformValue("view", viewMatrix);
    m_program->setUniformValue("projection", projectionMatrix);
    m_program->setUniformValue("lineColor", QVector3D(m_lineColor.redF(), m_lineColor.greenF(), m_lineColor.blueF()));

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    if (m_glFuncs)
    {
        m_glFuncs->glDrawArrays(GL_LINES, 0, m_numVerticesToRender);
    }

    m_program->release();
}

void ConnectionLineRenderer::cleanup()
{
    qCDebug(connectionLineRendererLog) << "Cleaning up ConnectionLineRenderer resources...";
    if (!m_initialized) return;

    m_vao.destroy();
    m_vbo.destroy();

    if (m_program)
    {
        delete m_program;
        m_program = nullptr;
    }
    m_initialized = false;
    m_numVerticesToRender = 0;
    m_glFuncs = nullptr;
    qCDebug(connectionLineRendererLog) << "ConnectionLineRenderer resources cleaned up.";
}
