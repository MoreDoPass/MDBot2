#ifndef CAMERA_H
#define CAMERA_H

#include <QVector3D>
#include <QMatrix4x4>
#include <QSet>  // Для обработки клавиш, если методы будут принимать QSet

// Пока не будем включать QLoggingCategory здесь, сделаем это в .cpp если понадобится для камеры специфичное логирование

/**
 * @brief Управляет положением, ориентацией и параметрами проекции (FOV) камеры в 3D-сцене.
 *
 * Предоставляет методы для перемещения и вращения камеры на основе ввода пользователя,
 * а также для получения матрицы вида (view matrix) и текущего угла обзора (FOV).
 * Используется классом Map3DView для навигации в трехмерном пространстве редактора карт.
 */
class Camera
{
   public:
    /**
     * @brief Перечисление для определения направлений движения камеры.
     * Может использоваться для передачи команд движения камере из различных источников ввода.
     */
    enum class MovementDirection
    {
        FORWARD,   ///< Движение вперед
        BACKWARD,  ///< Движение назад
        LEFT,      ///< Движение влево
        RIGHT,     ///< Движение вправо
        UP,        ///< Движение вверх
        DOWN       ///< Движение вниз
    };

    /**
     * @brief Конструктор камеры.
     * @param position Начальная позиция камеры в мировых координатах.
     * @param up Вектор "вверх" для мировых координат (обычно (0,0,1) или (0,1,0) в зависимости от конвенции).
     * @param yaw Начальный угол рыскания (вокруг вертикальной оси) в градусах.
     * @param pitch Начальный угол тангажа (вокруг горизонтальной оси) в градусах.
     */
    Camera(QVector3D position = QVector3D(0.0f, 2.0f, 5.0f), QVector3D up = QVector3D(0.0f, 1.0f, 0.0f),
           float yaw = DEFAULT_YAW, float pitch = DPITCH);

    // Методы для получения матриц
    QMatrix4x4 getViewMatrix() const;
    // QMatrix4x4 getProjectionMatrix(float aspectRatio) const; // Если камера будет строить и проекцию
    float getFov() const;
    QVector3D getPosition() const;
    float getYaw() const;
    float getPitch() const;

    // Новые методы для управления проекцией
    void setProjection(float fov, float aspectRatio, float nearPlane, float farPlane);
    QMatrix4x4 getProjectionMatrix() const;

    // Методы для обработки ввода
    // dt (deltaTime) - время, прошедшее с последнего кадра, для независимости от FPS
    void processKeyboard(const QSet<int>& pressedKeys, float deltaTime);
    void processMouseMovement(float xoffset, float yoffset, bool constrainPitch = true);
    void processMouseScroll(float yoffset);

    // TODO: Возможно, методы для прямого управления позицией/ориентацией, если нужно
    void setPosition(const QVector3D& position);
    void setYawPitch(float yaw, float pitch);
    void setYaw(float yaw);
    void setPitch(float pitch);

    void updateCameraVectors();  // Вспомогательный метод для пересчета Front, Right, Up векторов из Yaw/Pitch

   private:
    // Матрицы
    QMatrix4x4 m_viewMatrix;        // Уже должна быть неявно через getViewMatrix()
    QMatrix4x4 m_projectionMatrix;  // <--- ДОБАВЛЕНО

    // Параметры камеры
    QVector3D m_position;
    QVector3D m_front;    // Куда смотрит
    QVector3D m_up;       // Локальный "верх" камеры (не мировой Y)
    QVector3D m_right;    // Локальное "право" камеры
    QVector3D m_worldUp;  // Мировой "верх" (обычно (0,1,0)) - для пересчета Right и Up

    // Углы Эйлера
    float m_yaw;
    float m_pitch;

    // Настройки камеры
    float m_movementSpeed;  // Скорость движения
    float m_mouseSensitivity;
    float m_fov;  // Угол обзора (Field of View)

    // Параметры для управления проекцией, чтобы камера могла сама себя обновлять
    float m_aspectRatio;
    float m_nearPlane;
    float m_farPlane;

    // Для обработки мыши (эти значения Map3DView будет передавать)
    // float m_lastMouseX; // Не нужны здесь, т.к. смещения (xoffset, yoffset) передаются в processMouseMovement
    // float m_lastMouseY;
    // bool m_firstMouse;

    // Начальные значения по умолчанию, если не переданы в конструктор
    static constexpr float DPITCH = 0.0f;
    static constexpr float DEFAULT_YAW = -90.0f;
    static constexpr float DEFAULT_SPEED = 2.5f;
    static constexpr float DEFAULT_SENSITIVITY = 0.1f;
    static constexpr float DEFAULT_FOV = 45.0f;
};

#endif  // CAMERA_H
