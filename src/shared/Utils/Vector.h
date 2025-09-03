#pragma once

/**
 * @struct Vector3
 * @brief Представляет 3D-вектор или точку в пространстве.
 */
struct Vector3
{
    float x, y, z;

    /**
     * @brief Конструктор по умолчанию (создает нулевой вектор).
     */
    Vector3() : x(0.0f), y(0.0f), z(0.0f) {}

    /**
     * @brief Конструктор с инициализацией компонентов.
     * @param x - Компонент X.
     * @param y - Компонент Y.
     * @param z - Компонент Z.
     */
    Vector3(float x, float y, float z) : x(x), y(y), z(z) {}

    /**
     * @brief Рассчитывает квадрат расстояния до другой точки.
     * @details Быстрее, чем обычный Distance, так как не использует извлечение корня.
     *          Идеально для сравнения расстояний ("что ближе?").
     */
    float DistanceSq(const Vector3& other) const
    {
        float dx = x - other.x;
        float dy = y - other.y;
        float dz = z - other.z;
        return dx * dx + dy * dy + dz * dz;
    }
};
