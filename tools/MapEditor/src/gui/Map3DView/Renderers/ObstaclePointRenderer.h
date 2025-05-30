#ifndef OBSTACLEPOINTRENDERER_H
#define OBSTACLEPOINTRENDERER_H

#include <QOpenGLShaderProgram>
#include <QOpenGLVertexArrayObject>
#include <QOpenGLBuffer>
#include <QList>
#include <QMatrix4x4>
#include <QVector3D>
#include <QColor>

class QOpenGLFunctions;
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(obstaclePointRendererLog)

class ObstaclePointRenderer
{
   public:
    ObstaclePointRenderer();
    ~ObstaclePointRenderer();

    void initialize(QOpenGLFunctions* functions);
    void updateData(const QList<QVector3D>& points);
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
    int m_numPointsToRender = 0;

    const QColor m_pointColor = Qt::white;  // Цвет точек

    // Исходный код шейдеров
    const char* point_vshader_source = R"glsl(
        #version 330 core
        layout (location = 0) in vec3 aPos;
        uniform mat4 view;
        uniform mat4 projection;
        uniform vec3 pointColor_vs; 

        out vec3 PointColor_fs;

        void main()
        {
            gl_Position = projection * view * vec4(aPos, 1.0);
            gl_PointSize = 10.0; // Фиксированный размер точек
            PointColor_fs = pointColor_vs;
        }
    )glsl";

    const char* point_fshader_source = R"glsl(
        #version 330 core
        out vec4 FragColor;
        in vec3 PointColor_fs;

        void main()
        {
            // Для создания круглых точек, если стандартные квадратные не устраивают:
            // vec2 circCoord = 2.0 * gl_PointCoord - 1.0;
            // if (dot(circCoord, circCoord) > 1.0) {
            //     discard;
            // }
            FragColor = vec4(PointColor_fs, 1.0);
        }
    )glsl";
};

#endif  // OBSTACLEPOINTRENDERER_H
