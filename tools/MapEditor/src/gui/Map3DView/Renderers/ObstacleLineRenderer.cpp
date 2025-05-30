#include "ObstacleLineRenderer.h"
#include <QOpenGLFunctions>
#include <QDebug>

Q_LOGGING_CATEGORY(obstacleLineRendererLog, "qt.mapeditor.obstaclelinerenderer")

ObstacleLineRenderer::ObstacleLineRenderer()
    : m_glFuncs(nullptr), m_program(nullptr), m_initialized(false), m_numVerticesToRender(0)
{
    qCDebug(obstacleLineRendererLog) << "ObstacleLineRenderer constructor called";
}

ObstacleLineRenderer::~ObstacleLineRenderer()
{
    qCDebug(obstacleLineRendererLog) << "ObstacleLineRenderer destructor called";
    if (m_initialized)
    {
        cleanup();
    }
}

void ObstacleLineRenderer::initialize(QOpenGLFunctions* functions)
{
    if (!functions)
    {
        qCCritical(obstacleLineRendererLog) << "initialize: QOpenGLFunctions instance is null!";
        return;
    }
    m_glFuncs = functions;
    qCDebug(obstacleLineRendererLog) << "Initializing ObstacleLineRenderer...";

    m_program = new QOpenGLShaderProgram();

    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Vertex, line_vshader_source))
    {
        qCCritical(obstacleLineRendererLog) << "Vertex shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Fragment, line_fshader_source))
    {
        qCCritical(obstacleLineRendererLog) << "Fragment shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->link())
    {
        qCCritical(obstacleLineRendererLog) << "Shader program linking failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    qCDebug(obstacleLineRendererLog) << "Line shaders compiled and linked successfully.";

    m_vao.create();
    m_vbo.create();
    m_vbo.setUsagePattern(QOpenGLBuffer::DynamicDraw);

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    m_vbo.bind();

    m_program->enableAttributeArray(0);                                     // aPos
    m_program->setAttributeBuffer(0, GL_FLOAT, 0, 3, 3 * sizeof(GLfloat));  // X,Y,Z, stride = 3 floats

    m_vbo.release();
    qCDebug(obstacleLineRendererLog) << "VAO and VBO created, attributes configured.";
    m_initialized = true;
}

void ObstacleLineRenderer::updateData(const QList<QVector3D>& points, const QVector3D& currentMouseWorldPos)
{
    if (!m_initialized)
    {
        qCWarning(obstacleLineRendererLog) << "updateData called before initialization.";
        return;
    }

    qCDebug(obstacleLineRendererLog) << "Updating line data for" << points.size() << "points and mouse at"
                                     << currentMouseWorldPos;

    QVector<GLfloat> lineVertexData;
    // Резервируем место: (кол-во точек - 1) * 2 вершины для существующих линий + 2 вершины для линии до курсора.
    // Каждая вершина 3 float.
    if (!points.isEmpty())
    {
        lineVertexData.reserve((points.size() * 2) * 3);
    }

    for (int i = 0; i < points.size(); ++i)
    {
        const QVector3D& p1 = points[i];
        lineVertexData.append(p1.x());
        lineVertexData.append(p1.y());
        lineVertexData.append(p1.z());

        if (i + 1 < points.size())
        {
            const QVector3D& p2 = points[i + 1];
            lineVertexData.append(p2.x());
            lineVertexData.append(p2.y());
            lineVertexData.append(p2.z());
        }
        else  // Это последняя точка, рисуем линию до курсора, если курсор валидный
        {
            if (!currentMouseWorldPos.isNull())
            {
                lineVertexData.append(currentMouseWorldPos.x());
                lineVertexData.append(currentMouseWorldPos.y());
                lineVertexData.append(currentMouseWorldPos.z());
            }
        }
    }

    m_numVerticesToRender = lineVertexData.size() / 3;

    if (m_numVerticesToRender > 0)
    {
        m_vbo.bind();
        m_vbo.allocate(lineVertexData.constData(), lineVertexData.size() * sizeof(GLfloat));
        m_vbo.release();
        qCDebug(obstacleLineRendererLog) << "VBO updated with" << m_numVerticesToRender << "vertices for lines.";
    }
    else
    {
        m_vbo.bind();
        m_vbo.allocate(nullptr, 0);  // Очищаем VBO
        m_vbo.release();
        qCDebug(obstacleLineRendererLog) << "No line vertices to render, VBO cleared.";
    }
}

void ObstacleLineRenderer::render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix)
{
    if (!m_initialized || m_numVerticesToRender == 0 || !m_program || !m_program->isLinked() || !m_glFuncs)
    {
        return;
    }

    m_program->bind();
    m_program->setUniformValue("view", viewMatrix);
    m_program->setUniformValue("projection", projectionMatrix);
    m_program->setUniformValue("lineColor_fs",
                               QVector3D(m_lineColor.redF(), m_lineColor.greenF(), m_lineColor.blueF()));

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    m_glFuncs->glDrawArrays(GL_LINES, 0, m_numVerticesToRender);

    m_program->release();
}

void ObstacleLineRenderer::cleanup()
{
    qCDebug(obstacleLineRendererLog) << "Cleaning up ObstacleLineRenderer resources...";
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
    qCDebug(obstacleLineRendererLog) << "ObstacleLineRenderer resources cleaned up.";
}
