#ifndef WAYPOINTRENDERER_H
#define WAYPOINTRENDERER_H

#include <QOpenGLShaderProgram>
#include <QOpenGLVertexArrayObject>
#include <QOpenGLBuffer>
#include <QList>
#include <QMatrix4x4>
#include <QVector3D>
#include <QColor>  // For QColor

// Путь к Waypoint.h должен быть корректным относительно этого файла.
// Если WaypointRenderer.h в tools/MapEditor/src/gui/Map3DView/Renderers/
// а Waypoint.h в tools/MapEditor/src/core/MapData/
// то путь будет ../../../core/MapData/Waypoint.h
#include "../../../core/MapData/Waypoint.h"

class QOpenGLFunctions;  // Forward declaration для QOpenGLFunctions

// Логирование
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(waypointRendererLog)

class WaypointRenderer
{
   public:
    WaypointRenderer();
    ~WaypointRenderer();

    // Инициализация (шейдеры, VAO, VBO)
    void initialize(QOpenGLFunctions* functions);

    // Обновление данных вейпоинтов для отрисовки
    void updateData(const QList<Waypoint>& waypoints, int selectedWaypointId);

    // Отрисовка вейпоинтов
    void render(const QMatrix4x4& viewMatrix, const QMatrix4x4& projectionMatrix);

    // Освобождение ресурсов OpenGL
    void cleanup();

    bool isInitialized() const
    {
        return m_initialized;
    }

   private:
    QOpenGLFunctions* m_glFuncs;  // Указатель на функции OpenGL, будет инициализирован в initialize()
    QOpenGLShaderProgram* m_program;
    QOpenGLVertexArrayObject m_vao;
    QOpenGLBuffer m_vbo;  // Один VBO для координат и цвета

    bool m_initialized;
    int m_numWaypointsToRender;  // Количество точек для отрисовки

    // Цвета
    const QColor m_normalColor = Qt::red;
    const QColor m_selectedColor = Qt::yellow;

    // Строки с исходным кодом шейдеров
    // Их можно будет позже вынести в .glsl файлы
    const char* waypoint_vshader_source = R"glsl(
        #version 330 core
        layout (location = 0) in vec3 aPos;
        layout (location = 1) in vec3 aColor;
        uniform mat4 view;
        uniform mat4 projection;
        out vec3 nuestroColor;
        void main()
        {
            vec4 viewPos = view * vec4(aPos, 1.0);
            float distanceToCamera = length(viewPos.xyz);
            const float K_SIZE_SCALER = 200.0;
            float pointSize = K_SIZE_SCALER / distanceToCamera;
            gl_PointSize = clamp(pointSize, 2.0, 100.0); // Минимальный размер 2, максимальный 100
            gl_Position = projection * viewPos;
            nuestroColor = aColor;
        }
    )glsl";

    const char* waypoint_fshader_source = R"glsl(
        #version 330 core
        in vec3 nuestroColor;
        out vec4 FragColor;
        void main()
        {
            FragColor = vec4(nuestroColor, 1.0);
        }
    )glsl";
};

#endif  // WAYPOINTRENDERER_H
