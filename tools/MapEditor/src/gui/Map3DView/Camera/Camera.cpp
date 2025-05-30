#include "Camera.h"
#include <QtMath>  // Для qDegreesToRadians и других математических функций
#include <QDebug>  // Для возможной отладки

// Если понадобится специфичное логирование для камеры:
// #include <QLoggingCategory>
// Q_LOGGING_CATEGORY(cameraLog, "qt.mapeditor.camera")

Camera::Camera(QVector3D position, QVector3D up, float yaw, float pitch)
    : m_position(position),
      m_worldUp(up),
      m_yaw(yaw),
      m_pitch(pitch),
      m_front(QVector3D(0.0f, 0.0f, -1.0f)),  // Начальное направление
      m_movementSpeed(DEFAULT_SPEED),
      m_mouseSensitivity(DEFAULT_SENSITIVITY),
      m_fov(DEFAULT_FOV)
      // Инициализируем поля для проекции значениями по умолчанию или нулевыми,
      // они все равно будут установлены при первом вызове setProjection из resizeGL
      ,
      m_aspectRatio(16.0f / 9.0f)  // Типичное соотношение
      ,
      m_nearPlane(0.1f),
      m_farPlane(10000.0f)
{
    // qCDebug(cameraLog) << "Camera constructor called";
    updateCameraVectors();
}

void Camera::updateCameraVectors()
{
    // qCDebug(cameraLog) << "Camera::updateCameraVectors called. Yaw:" << m_yaw << "Pitch:" << m_pitch;
    // qDebug() << "Camera::updateCameraVectors called. Yaw:" << m_yaw << "Pitch:" << m_pitch;
    // Рассчитываем новый вектор Front
    QVector3D front;
    front.setX(qCos(qDegreesToRadians(m_yaw)) * qCos(qDegreesToRadians(m_pitch)));
    front.setY(qSin(qDegreesToRadians(m_pitch)));
    front.setZ(qSin(qDegreesToRadians(m_yaw)) * qCos(qDegreesToRadians(m_pitch)));
    m_front = front.normalized();

    // Также пересчитываем векторы Right и Up
    m_right = QVector3D::crossProduct(m_front, m_worldUp).normalized();
    m_up = QVector3D::crossProduct(m_right, m_front).normalized();

    // Обновляем матрицу вида
    m_viewMatrix.setToIdentity();
    m_viewMatrix.lookAt(m_position, m_position + m_front, m_up);
}

QMatrix4x4 Camera::getViewMatrix() const
{
    return m_viewMatrix;
}

float Camera::getFov() const
{
    return m_fov;
}

QVector3D Camera::getPosition() const
{
    return m_position;
}

float Camera::getYaw() const
{
    return m_yaw;
}

float Camera::getPitch() const
{
    return m_pitch;
}

void Camera::processKeyboard(const QSet<int>& pressedKeys, float deltaTime)
{
    float velocity = m_movementSpeed * deltaTime;
    // qCDebug(cameraLog) << "Processing keyboard. Velocity:" << velocity << "DeltaTime:" << deltaTime;

    if (pressedKeys.contains(Qt::Key_W))
    {
        // qCDebug(cameraLog) << "Moving FORWARD";
        m_position += m_front * velocity;
    }
    if (pressedKeys.contains(Qt::Key_S))
    {
        // qCDebug(cameraLog) << "Moving BACKWARD";
        m_position -= m_front * velocity;
    }
    if (pressedKeys.contains(Qt::Key_A))
    {
        // qCDebug(cameraLog) << "Moving LEFT";
        m_position -= m_right * velocity;
    }
    if (pressedKeys.contains(Qt::Key_D))
    {
        // qCDebug(cameraLog) << "Moving RIGHT";
        m_position += m_right * velocity;
    }
    if (pressedKeys.contains(Qt::Key_Space) || pressedKeys.contains(Qt::Key_E))
    {
        // qCDebug(cameraLog) << "Moving UP";
        m_position += m_worldUp * velocity;
    }
    if (pressedKeys.contains(Qt::Key_Control) || pressedKeys.contains(Qt::Key_Q))
    {
        // qCDebug(cameraLog) << "Moving DOWN";
        m_position -= m_worldUp * velocity;
    }
    // qCDebug(cameraLog) << "New position:" << m_position;
    updateCameraVectors();
}

void Camera::processMouseMovement(float xoffset, float yoffset, bool constrainPitch)
{
    xoffset *= m_mouseSensitivity;
    yoffset *= m_mouseSensitivity;

    m_yaw += xoffset;
    m_pitch += yoffset;  // Обрати внимание: в Qt оконные координаты Y обычно инвертированы (вниз = +Y)
                         // Если yoffset уже инвертирован (например, y_current - y_last), то += правильно.
                         // Если yoffset это (y_last - y_current), то нужно будет -=.
                         // Стандартная практика OpenGL (как было в MyOpenGLWidget) - yoffset положительный вверх, тогда
                         // += правильно.

    // qCDebug(cameraLog) << "Processing mouse. Yaw:" << m_yaw << "Pitch:" << m_pitch << "XOffset:" << xoffset <<
    // "YOffset:" << yoffset;

    if (constrainPitch)
    {
        if (m_pitch > 89.0f) m_pitch = 89.0f;
        if (m_pitch < -89.0f) m_pitch = -89.0f;
    }
    // qCDebug(cameraLog) << "Constrained Pitch:" << m_pitch;
    updateCameraVectors();
}

void Camera::processMouseScroll(float yoffset)
{
    // qCDebug(cameraLog) << "Processing scroll. YOffset:" << yoffset;
    m_fov -= yoffset;  // Обычно yoffset от колеса мыши: положительный при прокрутке вперед/вверх, отрицательный
                       // назад/вниз Уменьшение FOV = приближение, увеличение = отдаление.
    if (m_fov < 1.0f) m_fov = 1.0f;
    if (m_fov > 75.0f)  // Ограничим максимальный FOV
        m_fov = 75.0f;
    // qCDebug(cameraLog) << "New FOV:" << m_fov;

    // Обновляем матрицу проекции с новым FOV и сохраненными параметрами
    setProjection(m_fov, m_aspectRatio, m_nearPlane, m_farPlane);
}

void Camera::setProjection(float fov, float aspectRatio, float nearPlane, float farPlane)
{
    m_fov = fov;  // Обновляем FOV камеры
    // Сохраняем параметры для последующего использования (например, в processMouseScroll)
    m_aspectRatio = aspectRatio;
    m_nearPlane = nearPlane;
    m_farPlane = farPlane;

    m_projectionMatrix.setToIdentity();
    m_projectionMatrix.perspective(m_fov, m_aspectRatio, m_nearPlane, m_farPlane);
}

QMatrix4x4 Camera::getProjectionMatrix() const
{
    return m_projectionMatrix;
}

// Новые сеттеры
void Camera::setPosition(const QVector3D& position)
{
    // qCDebug(cameraLog) << "Camera::setPosition called with:" << position;
    qDebug() << "Camera::setPosition called with:" << position;
    m_position = position;
    // При простом изменении позиции обычно не нужно пересчитывать векторы ориентации (Front, Right, Up),
    // если только у нас нет логики, где позиция влияет на цель взгляда (например, камера всегда смотрит в (0,0,0)).
    // В нашем случае, Front вектор остается тем же, камера просто перемещается.
    // Матрица вида (view matrix) изменится, так как она зависит от m_position.
    // updateCameraVectors(); // НЕ НУЖНО здесь, если setPosition не меняет ориентацию
}

void Camera::setYaw(float yaw)
{
    // qCDebug(cameraLog) << "Camera::setYaw called with:" << yaw;
    qDebug() << "Camera::setYaw called with:" << yaw;
    m_yaw = yaw;
    updateCameraVectors();
}

void Camera::setPitch(float pitch)
{
    // qCDebug(cameraLog) << "Camera::setPitch called with:" << pitch;
    qDebug() << "Camera::setPitch called with:" << pitch;
    m_pitch = pitch;
    // Ограничиваем pitch, чтобы избежать переворота камеры
    if (m_pitch > 89.0f) m_pitch = 89.0f;
    if (m_pitch < -89.0f) m_pitch = -89.0f;
    updateCameraVectors();
}

void Camera::setYawPitch(float yaw, float pitch)
{
    // qCDebug(cameraLog) << "Camera::setYawPitch called with Yaw:" << yaw << "Pitch:" << pitch;
    qDebug() << "Camera::setYawPitch called with Yaw:" << yaw << "Pitch:" << pitch;
    m_yaw = yaw;
    m_pitch = pitch;
    updateCameraVectors();  // После изменения углов всегда нужно обновлять векторы
}
