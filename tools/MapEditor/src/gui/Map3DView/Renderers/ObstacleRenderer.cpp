#include "ObstacleRenderer.h"
#include <QOpenGLFunctions>
#include <QDebug>

// Определение категории логирования
Q_LOGGING_CATEGORY(obstacleRendererLog, "qt.mapeditor.obstaclerenderer")

ObstacleRenderer::ObstacleRenderer()
    : m_glFuncs(nullptr), m_program(nullptr), m_initialized(false), m_numVerticesToRender(0)
{
    qCDebug(obstacleRendererLog) << "ObstacleRenderer constructor called";
}

ObstacleRenderer::~ObstacleRenderer()
{
    qCDebug(obstacleRendererLog) << "ObstacleRenderer destructor called";
    if (m_initialized)
    {
        cleanup();
    }
}

void ObstacleRenderer::initialize(QOpenGLFunctions* functions)
{
    if (!functions)
    {
        qCCritical(obstacleRendererLog) << "initialize: QOpenGLFunctions instance is null!";
        return;
    }
    m_glFuncs = functions;
    qCDebug(obstacleRendererLog) << "Initializing ObstacleRenderer...";

    m_program = new QOpenGLShaderProgram();

    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Vertex, obstacle_vshader_source))
    {
        qCCritical(obstacleRendererLog) << "Vertex shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Fragment, obstacle_fshader_source))
    {
        qCCritical(obstacleRendererLog) << "Fragment shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->link())
    {
        qCCritical(obstacleRendererLog) << "Shader program linking failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    qCDebug(obstacleRendererLog) << "Obstacle shaders compiled and linked successfully.";

    m_vao.create();
    m_vbo.create();
    m_vbo.setUsagePattern(QOpenGLBuffer::DynamicDraw);  // Данные могут меняться

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    m_vbo.bind();

    m_program->enableAttributeArray(0);                                     // aPos
    m_program->setAttributeBuffer(0, GL_FLOAT, 0, 3, 3 * sizeof(GLfloat));  // X,Y,Z, stride = 3 floats

    m_vbo.release();
    qCDebug(obstacleRendererLog) << "VAO and VBO created, attributes configured.";
    m_initialized = true;
}

void ObstacleRenderer::updateData(const QList<Obstacle>& obstacles)
{
    if (!m_initialized)
    {
        qCWarning(obstacleRendererLog) << "updateData called before initialization.";
        return;
    }

    qCDebug(obstacleRendererLog) << "Updating obstacle data for" << obstacles.size() << "obstacles.";

    QVector<GLfloat> obstacleVertexData;
    // Резервируем место: каждый полигон V0..Vn-1 дает n линий, каждая линия 2 вершины, каждая вершина 3 float.
    // Грубая оценка: obstacles.size() * MAX_VERTICES_PER_OBSTACLE * 2 * 3
    // Для примера, если в среднем 10 вершин на препятствие: obstacles.size() * 10 * 6
    obstacleVertexData.reserve(obstacles.size() * 60);  // Примерное резервирование

    for (const auto& obstacle : obstacles)
    {
        if (!obstacle.shapeVertices.isEmpty())
        {
            const QList<QVector3D>& shape = obstacle.shapeVertices;
            int n = shape.size();

            if (n >= 2)  // Нужно как минимум 2 точки для линии
            {
                for (int i = 0; i < n; ++i)
                {
                    const QVector3D& p1 = shape[i];
                    const QVector3D& p2 = shape[(i + 1) % n];  // Замыкаем на первую точку

                    obstacleVertexData.append(p1.x());
                    obstacleVertexData.append(p1.y());
                    obstacleVertexData.append(p1.z());

                    obstacleVertexData.append(p2.x());
                    obstacleVertexData.append(p2.y());
                    obstacleVertexData.append(p2.z());
                }
                qCDebug(obstacleRendererLog) << "Obstacle ID" << obstacle.id << " (shape type): processed" << n
                                             << "vertices, generated" << n << "lines for boundary.";
            }
            else
            {
                qCDebug(obstacleRendererLog) << "Obstacle ID" << obstacle.id << " (shape type): has" << n
                                             << "vertices, not enough for a line. Skipping.";
            }
        }
        // Если shapeVertices пуст, но есть baseVertices и height (старый формат призмы)
        // Можно добавить сюда старую логику генерации призмы, если нужна обратная совместимость
        // или если мы хотим поддерживать оба типа препятствий.
        // Пока что, для чистоты, я ее не включаю.
        else if (!obstacle.baseVertices.isEmpty() && obstacle.obstacleHeight > 0.0f)
        {
            qCDebug(obstacleRendererLog) << "Obstacle ID" << obstacle.id
                                         << " (prism type): using baseVertices and height. Prism rendering NOT YET "
                                            "RE-IMPLEMENTED in this version of updateData. Skipping.";
            // Сюда можно скопировать старый код для генерации вершин призмы, если нужно.
            // Например:
            // const QList<QVector3D>& base = obstacle.baseVertices;
            // float height = obstacle.obstacleHeight;
            // int numBaseVertices = base.size();
            // QVector3D offset(0, height, 0);
            // // 1. Нижнее основание ...
            // // 2. Верхнее основание ...
            // // 3. Боковые грани ...
        }
        else
        {
            qCDebug(obstacleRendererLog) << "Obstacle ID" << obstacle.id
                                         << "has no shapeVertices and no valid baseVertices/height. Skipping.";
        }
    }

    m_numVerticesToRender = obstacleVertexData.size() / 3;  // Каждая вершина - 3 float

    if (m_numVerticesToRender > 0)
    {
        m_vbo.bind();
        m_vbo.allocate(obstacleVertexData.constData(), obstacleVertexData.size() * sizeof(GLfloat));
        m_vbo.release();
        qCDebug(obstacleRendererLog) << "VBO updated with" << m_numVerticesToRender << "vertices for obstacles.";
    }
    else
    {
        m_vbo.bind();
        m_vbo.allocate(nullptr, 0);  // Очищаем VBO, если нет препятствий
        m_vbo.release();
        qCDebug(obstacleRendererLog) << "No renderable obstacle vertices generated, VBO cleared.";
    }
}

void ObstacleRenderer::render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix)
{
    if (!m_initialized || m_numVerticesToRender == 0 || !m_program || !m_program->isLinked())
    {
        return;
    }

    m_program->bind();
    QMatrix4x4 modelMatrix;  // Единичная, т.к. вершины в мировых координатах
    m_program->setUniformValue("model", modelMatrix);
    m_program->setUniformValue("view", viewMatrix);
    m_program->setUniformValue("projection", projectionMatrix);
    m_program->setUniformValue("lineColor",
                               QVector3D(m_obstacleColor.redF(), m_obstacleColor.greenF(), m_obstacleColor.blueF()));

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    if (m_glFuncs)
    {
        // Используем GL_LINES для отрисовки границ
        m_glFuncs->glDrawArrays(GL_LINES, 0, m_numVerticesToRender);
    }

    m_program->release();
}

void ObstacleRenderer::cleanup()
{
    qCDebug(obstacleRendererLog) << "Cleaning up ObstacleRenderer resources...";
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
    qCDebug(obstacleRendererLog) << "ObstacleRenderer resources cleaned up.";
}
