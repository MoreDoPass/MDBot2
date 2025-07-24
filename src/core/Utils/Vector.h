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
};