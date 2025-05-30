#include "PlayerMarkerRenderer.h"
#include <QOpenGLFunctions>
#include <QDebug>

// Определение категории логирования
Q_LOGGING_CATEGORY(playerMarkerRendererLog, "qt.mapeditor.playermarkerrenderer")

// Статические данные для геометрии куба (можно вынести в .h или оставить здесь)
static const GLfloat cube_vertices_pmr[] = {
    // Передняя грань
    -0.5f, -0.5f, 0.5f, 0.5f, -0.5f, 0.5f, 0.5f, 0.5f, 0.5f, -0.5f, 0.5f, 0.5f,
    // Задняя грань
    -0.5f, -0.5f, -0.5f, 0.5f, -0.5f, -0.5f, 0.5f, 0.5f, -0.5f, -0.5f, 0.5f, -0.5f};

static const GLuint cube_indices_pmr[] = {
    0, 1, 2, 2, 3, 0,  // Передняя
    1, 5, 6, 6, 2, 1,  // Правая
    5, 4, 7, 7, 6, 5,  // Задняя
    4, 0, 3, 3, 7, 4,  // Левая
    3, 2, 6, 6, 7, 3,  // Верхняя
    4, 5, 1, 1, 0, 4   // Нижняя
};

PlayerMarkerRenderer::PlayerMarkerRenderer()
    : m_glFuncs(nullptr), m_program(nullptr), m_initialized(false), m_visible(false), m_indexCount(0)
{
    qCDebug(playerMarkerRendererLog) << "PlayerMarkerRenderer constructor called";
}

PlayerMarkerRenderer::~PlayerMarkerRenderer()
{
    qCDebug(playerMarkerRendererLog) << "PlayerMarkerRenderer destructor called";
    if (m_initialized)
    {
        cleanup();
    }
}

void PlayerMarkerRenderer::initialize(QOpenGLFunctions* functions)
{
    if (!functions)
    {
        qCCritical(playerMarkerRendererLog) << "initialize: QOpenGLFunctions instance is null!";
        return;
    }
    m_glFuncs = functions;
    qCDebug(playerMarkerRendererLog) << "Initializing PlayerMarkerRenderer...";

    m_program = new QOpenGLShaderProgram();
    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Vertex, cube_vshader_source))
    {
        qCCritical(playerMarkerRendererLog) << "Vertex shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->addShaderFromSourceCode(QOpenGLShader::Fragment, cube_fshader_source))
    {
        qCCritical(playerMarkerRendererLog) << "Fragment shader compilation failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    if (!m_program->link())
    {
        qCCritical(playerMarkerRendererLog) << "Shader program linking failed:" << m_program->log();
        delete m_program;
        m_program = nullptr;
        return;
    }
    qCDebug(playerMarkerRendererLog) << "Cube shaders compiled and linked successfully.";

    initCubeGeometry();  // Инициализируем геометрию
    m_initialized = true;
}

void PlayerMarkerRenderer::initCubeGeometry()
{
    if (!m_program || !m_program->isLinked() || !m_glFuncs)
    {
        qCCritical(playerMarkerRendererLog) << "Shader program not ready or GL functions not set for cube geometry.";
        return;
    }

    m_vao.create();
    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);

    m_vboVertices.create();
    m_vboVertices.bind();
    m_vboVertices.allocate(cube_vertices_pmr, sizeof(cube_vertices_pmr));

    m_glFuncs->glEnableVertexAttribArray(0);
    m_glFuncs->glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 3 * sizeof(GLfloat), nullptr);

    m_vboIndices.create();
    m_vboIndices.bind();
    m_vboIndices.allocate(cube_indices_pmr, sizeof(cube_indices_pmr));

    m_indexCount = sizeof(cube_indices_pmr) / sizeof(GLuint);
    qCDebug(playerMarkerRendererLog) << "Cube geometry initialized. Index count:" << m_indexCount;
    // VBOs остаются привязанными к VAO, отвязывать их здесь не нужно
}

void PlayerMarkerRenderer::updateData(const QVector3D& position, bool visible)
{
    m_position = position;
    m_visible = visible;
    // qCDebug(playerMarkerRendererLog) << "Updating player marker data. Position:" << position << "Visible:" <<
    // visible;
}

void PlayerMarkerRenderer::render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix)
{
    if (!m_initialized || !m_visible || !m_program || !m_program->isLinked() || m_indexCount == 0 || !m_glFuncs)
    {
        return;
    }

    m_program->bind();

    QMatrix4x4 modelMatrix;
    modelMatrix.translate(m_position);
    // modelMatrix.scale(1.0f); // Масштаб можно настроить здесь или сделать параметром

    m_program->setUniformValue("model", modelMatrix);
    m_program->setUniformValue("view", viewMatrix);
    m_program->setUniformValue("projection", projectionMatrix);
    m_program->setUniformValue("markerColor",
                               QVector3D(m_markerColor.redF(), m_markerColor.greenF(), m_markerColor.blueF()));

    QOpenGLVertexArrayObject::Binder vaoBinder(&m_vao);
    // Индексный буфер уже часть состояния VAO, дополнительно биндить его перед glDrawElements не нужно,
    // если он был привязан при настройке VAO.
    m_glFuncs->glDrawElements(GL_TRIANGLES, m_indexCount, GL_UNSIGNED_INT, 0);

    m_program->release();
}

void PlayerMarkerRenderer::cleanup()
{
    qCDebug(playerMarkerRendererLog) << "Cleaning up PlayerMarkerRenderer resources...";
    if (!m_initialized) return;

    // Уничтожаем VAO и VBO (VAO должен быть отвязан перед уничтожением VBO, если VBO - часть VAO)
    // QOpenGLVertexArrayObject::Binder сам отвяжет VAO при выходе из области видимости,
    // но для явности можно m_vao.release() если бы мы не использовали Binder в render().
    m_vao.destroy();
    m_vboVertices.destroy();
    m_vboIndices.destroy();

    if (m_program)
    {
        delete m_program;
        m_program = nullptr;
    }
    m_initialized = false;
    m_visible = false;
    m_indexCount = 0;
    m_glFuncs = nullptr;
    qCDebug(playerMarkerRendererLog) << "PlayerMarkerRenderer resources cleaned up.";
}
