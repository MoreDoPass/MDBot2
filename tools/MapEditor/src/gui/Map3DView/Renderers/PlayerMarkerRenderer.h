#ifndef PLAYERMARKERRENDERER_H
#define PLAYERMARKERRENDERER_H

#include <QOpenGLShaderProgram>
#include <QOpenGLVertexArrayObject>
#include <QOpenGLBuffer>
#include <QMatrix4x4>
#include <QVector3D>
#include <QColor>

class QOpenGLFunctions;  // Forward declaration

// Логирование
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(playerMarkerRendererLog)

class PlayerMarkerRenderer
{
   public:
    PlayerMarkerRenderer();
    ~PlayerMarkerRenderer();

    void initialize(QOpenGLFunctions* functions);
    // Позиция уже в координатах OpenGL, visible - показывать ли маркер
    void updateData(const QVector3D& position, bool visible);
    void render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix);
    void cleanup();

    bool isInitialized() const
    {
        return m_initialized;
    }

   private:
    void initCubeGeometry();  // Приватный метод для инициализации геометрии куба

    QOpenGLFunctions* m_glFuncs = nullptr;
    QOpenGLShaderProgram* m_program = nullptr;
    QOpenGLVertexArrayObject m_vao;
    QOpenGLBuffer m_vboVertices{QOpenGLBuffer::VertexBuffer};
    QOpenGLBuffer m_vboIndices{QOpenGLBuffer::IndexBuffer};

    bool m_initialized = false;
    bool m_visible = false;  // Показывать ли маркер
    QVector3D m_position;    // Позиция маркера в OGL координатах
    int m_indexCount = 0;    // Количество индексов для отрисовки куба

    const QColor m_markerColor = QColor(128, 179, 255);  // Светло-синий (0.5, 0.7, 1.0)

    // Шейдеры для куба (аналогичные тем, что были в Map3DView::initShaders)
    const char* cube_vshader_source = R"glsl(
        #version 330 core
        layout (location = 0) in vec3 aPos;
        uniform mat4 model;
        uniform mat4 view;
        uniform mat4 projection;
        void main()
        {
            gl_Position = projection * view * model * vec4(aPos, 1.0);
        }
    )glsl";

    const char* cube_fshader_source = R"glsl(
        #version 330 core
        out vec4 FragColor;
        uniform vec3 markerColor; // Цвет будет передаваться как uniform
        void main()
        {
            FragColor = vec4(markerColor, 1.0);
        }
    )glsl";
};

#endif  // PLAYERMARKERRENDERER_H
