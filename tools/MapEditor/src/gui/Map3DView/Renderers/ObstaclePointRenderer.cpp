#include "ObstaclePointRenderer.h"
#include <QOpenGLFunctions>
#include <QDebug>

Q_LOGGING_CATEGORY(obstaclePointRendererLog, "qt.mapeditor.obstaclepointrenderer")

ObstaclePointRenderer::ObstaclePointRenderer()
    : m_glFuncs(nullptr), m_program(nullptr), m_initialized(false), m_numPointsToRender(0)
{
    qCDebug(obstaclePointRendererLog) << "ObstaclePointRenderer constructor called";
}

ObstaclePointRenderer::~ObstaclePointRenderer()
{
    qCDebug(obstaclePointRendererLog) << "ObstaclePointRenderer destructor called";
    if (m_initialized)
    {
        cleanup();
    }
}

void ObstaclePointRenderer::initialize(QOpenGLFunctions* functions)
{
    if (!functions)
    {
        qCCritical(obstaclePointRendererLog) << "initialize: QOpenGLFunctions instance is null!";
        return;
    }
    m_glFuncs = functions;
    qCDebug(obstaclePointRendererLog) << "Initializing ObstaclePointRenderer...";

    m_program = new QOpenGLShaderProgram();

    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Vertex, point_vshader_source))
    {
        qCCritical(obstaclePointRendererLog) << "Vertex shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Fragment, point_fshader_source))
    {
        qCCritical(obstaclePointRendererLog) << "Fragment shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->link())
    {
        qCCritical(obstaclePointRendererLog) << "Shader program linking failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    qCDebug(obstaclePointRendererLog) << "Point shaders compiled and linked successfully.";

    m_vao.create();
    m_vbo.create();
    m_vbo.setUsagePattern(QOpenGLBuffer::DynamicDraw);

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    m_vbo.bind();

    m_program->enableAttributeArray(0);                                     // aPos
    m_program->setAttributeBuffer(0, GL_FLOAT, 0, 3, 3 * sizeof(GLfloat));  // X,Y,Z, stride = 3 floats

    m_vbo.release();
    qCDebug(obstaclePointRendererLog) << "VAO and VBO created, attributes configured.";
    m_initialized = true;
}

void ObstaclePointRenderer::updateData(const QList<QVector3D>& points)
{
    if (!m_initialized)
    {
        qCWarning(obstaclePointRendererLog) << "updateData called before initialization.";
        return;
    }

    qCDebug(obstaclePointRendererLog) << "Updating point data for" << points.size() << "points.";

    QVector<GLfloat> pointVertexData;
    pointVertexData.reserve(points.size() * 3);  // 3 floats per point (X,Y,Z)

    for (const QVector3D& pt : points)
    {
        pointVertexData.append(pt.x());
        pointVertexData.append(pt.y());
        pointVertexData.append(pt.z());
    }

    m_numPointsToRender = points.size();

    if (m_numPointsToRender > 0)
    {
        m_vbo.bind();
        m_vbo.allocate(pointVertexData.constData(), pointVertexData.size() * sizeof(GLfloat));
        m_vbo.release();
        qCDebug(obstaclePointRendererLog) << "VBO updated with" << m_numPointsToRender << "points.";
    }
    else
    {
        m_vbo.bind();
        m_vbo.allocate(nullptr, 0);  // Очищаем VBO, если нет точек
        m_vbo.release();
        qCDebug(obstaclePointRendererLog) << "No points to render, VBO cleared.";
    }
}

void ObstaclePointRenderer::render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix)
{
    if (!m_initialized || m_numPointsToRender == 0 || !m_program || !m_program->isLinked() || !m_glFuncs)
    {
        return;
    }

    m_program->bind();
    m_program->setUniformValue("view", viewMatrix);
    m_program->setUniformValue("projection", projectionMatrix);
    m_program->setUniformValue("pointColor_vs",
                               QVector3D(m_pointColor.redF(), m_pointColor.greenF(), m_pointColor.blueF()));

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    m_glFuncs->glEnable(GL_PROGRAM_POINT_SIZE);  // Для изменения размера точек в шейдере
    // m_glFuncs->glEnable(GL_POINT_SMOOTH); // Для сглаживания точек, если нужно и поддерживается
    // m_glFuncs->glDisable(GL_DEPTH_TEST); // Можно отключить тест глубины для точек, чтобы они всегда были видны

    m_glFuncs->glDrawArrays(GL_POINTS, 0, m_numPointsToRender);

    m_glFuncs->glDisable(GL_PROGRAM_POINT_SIZE);
    // m_glFuncs->glEnable(GL_DEPTH_TEST); // Включаем тест глубины обратно, если отключали

    m_program->release();
}

void ObstaclePointRenderer::cleanup()
{
    qCDebug(obstaclePointRendererLog) << "Cleaning up ObstaclePointRenderer resources...";
    if (!m_initialized) return;

    m_vao.destroy();
    m_vbo.destroy();

    if (m_program)
    {
        delete m_program;
        m_program = nullptr;
    }
    m_initialized = false;
    m_numPointsToRender = 0;
    m_glFuncs = nullptr;
    qCDebug(obstaclePointRendererLog) << "ObstaclePointRenderer resources cleaned up.";
}
