#ifndef CONNECTIONLINERENDERER_H
#define CONNECTIONLINERENDERER_H

#include <QOpenGLShaderProgram>
#include <QOpenGLVertexArrayObject>
#include <QOpenGLBuffer>
#include <QList>
#include <QMatrix4x4>
#include <QVector3D>
#include <QColor>

// Для доступа к данным Waypoint, чтобы знать, что с чем соединять
#include "../../../core/MapData/Waypoint.h"

class QOpenGLFunctions;  // Forward declaration

// Логирование
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(connectionLineRendererLog)

class ConnectionLineRenderer
{
   public:
    ConnectionLineRenderer();
    ~ConnectionLineRenderer();

    void initialize(QOpenGLFunctions* functions);
    void updateData(const QList<Waypoint>& waypoints);  // Линии зависят от вейпоинтов
    void render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix);
    void cleanup();

    bool isInitialized() const
    {
        return m_initialized;
    }

   private:
    QOpenGLFunctions* m_glFuncs;
    QOpenGLShaderProgram* m_program;
    QOpenGLVertexArrayObject m_vao;
    QOpenGLBuffer m_vbo;

    bool m_initialized;
    int m_numVerticesToRender;  // Количество вершин для отрисовки (линии состоят из пар вершин)

    const QColor m_lineColor = Qt::green;  // Цвет линий по умолчанию

    // Строки с исходным кодом шейдеров
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
        uniform vec3 lineColor; // Цвет будет передаваться как uniform
        void main()
        {
            FragColor = vec4(lineColor, 1.0);
        }
    )glsl";
};

#endif  // CONNECTIONLINERENDERER_H
