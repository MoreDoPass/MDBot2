#ifndef OBSTACLELINERENDERER_H
#define OBSTACLELINERENDERER_H

#include <QOpenGLShaderProgram>
#include <QOpenGLVertexArrayObject>
#include <QOpenGLBuffer>
#include <QList>
#include <QMatrix4x4>
#include <QVector3D>
#include <QPoint>  // Для currentMouseWorldPos
#include <QColor>

class QOpenGLFunctions;
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(obstacleLineRendererLog)

class ObstacleLineRenderer
{
   public:
    ObstacleLineRenderer();
    ~ObstacleLineRenderer();

    void initialize(QOpenGLFunctions* functions);
    // points - уже установленные точки, currentMouseWorldPos - текущая позиция курсора в мировых координатах (для
    // "резиновой" линии)
    void updateData(const QList<QVector3D>& points, const QVector3D& currentMouseWorldPos);
    void render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix);
    void cleanup();

    bool isInitialized() const
    {
        return m_initialized;
    }

   private:
    QOpenGLFunctions* m_glFuncs = nullptr;
    QOpenGLShaderProgram* m_program = nullptr;
    QOpenGLVertexArrayObject m_vao;
    QOpenGLBuffer m_vbo;

    bool m_initialized = false;
    int m_numVerticesToRender = 0;

    const QColor m_lineColor = Qt::white;  // Цвет линий

    // Исходный код шейдеров (может быть таким же, как у ConnectionLineRenderer или PointRenderer)
    const char* line_vshader_source = R"glsl(
        #version 330 core
        layout (location = 0) in vec3 aPos;
        uniform mat4 view;
        uniform mat4 projection;
        void main()
        {
            gl_Position = projection * view * vec4(aPos, 1.0);
        }
    )glsl";

    const char* line_fshader_source = R"glsl(
        #version 330 core
        out vec4 FragColor;
        uniform vec3 lineColor_fs; // Цвет будет передаваться как uniform
        void main()
        {
            FragColor = vec4(lineColor_fs, 1.0);
        }
    )glsl";
};

#endif  // OBSTACLELINERENDERER_H
