#ifndef OBSTACLERENDERER_H
#define OBSTACLERENDERER_H

#include <QOpenGLShaderProgram>
#include <QOpenGLVertexArrayObject>
#include <QOpenGLBuffer>
#include <QList>
#include <QMatrix4x4>
#include <QVector3D>
#include <QColor>

#include "../../../core/MapData/MapData.h"  // Для структуры Obstacle

class QOpenGLFunctions;  // Forward declaration

// Логирование
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(obstacleRendererLog)

class ObstacleRenderer
{
   public:
    ObstacleRenderer();
    ~ObstacleRenderer();

    void initialize(QOpenGLFunctions* functions);
    void updateData(const QList<Obstacle>& obstacles);
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
    QOpenGLBuffer m_vbo;  // Буфер для вершин препятствий

    bool m_initialized = false;
    int m_numVerticesToRender = 0;  // Количество вершин для отрисовки

    const QColor m_obstacleColor = QColor(153, 25, 25);  // Темно-красный цвет для препятствий (0.6, 0.1, 0.1)

    // Строки с исходным кодом шейдеров (аналогично шейдерам из Map3DView::initObstacleShaders)
    const char* obstacle_vshader_source = R"glsl(
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

    const char* obstacle_fshader_source = R"glsl(
        #version 330 core
        out vec4 FragColor;
        uniform vec3 lineColor; // Используем lineColor для единообразия, хотя это полигоны
        void main()
        {
            FragColor = vec4(lineColor, 1.0);
        }
    )glsl";
};

#endif  // OBSTACLERENDERER_H
