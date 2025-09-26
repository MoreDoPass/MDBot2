#pragma once
#include <cmath>  // Подключаем стандартную математическую библиотеку для sqrt

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

    // --- НОВЫЙ КОД, КОТОРЫЙ МЫ ДОБАВЛЯЕМ ---

    /**
     * @brief Перегрузка оператора вычитания для двух векторов.
     * @details Создает новый вектор, направленный от 'other' к 'this'.
     *          Используется для нахождения вектора направления.
     * @return Результирующий вектор.
     */
    Vector3 operator-(const Vector3& other) const
    {
        return Vector3(x - other.x, y - other.y, z - other.z);
    }

    /**
     * @brief Перегрузка оператора умножения вектора на число (скаляр).
     * @details "Растягивает" или "сжимает" вектор, сохраняя его направление.
     * @return Результирующий, масштабированный вектор.
     */
    Vector3 operator*(float scalar) const
    {
        return Vector3(x * scalar, y * scalar, z * scalar);
    }

    /**
     * @brief Вычисляет длину (величину) вектора.
     * @details Использует теорему Пифагора. Обратите внимание, что это
     *          относительно медленная операция из-за sqrt.
     * @return Длина вектора.
     */
    float Length() const
    {
        return sqrt(x * x + y * y + z * z);
    }

    /**
     * @brief Нормализует вектор, делая его длину равной 1.
     * @details Изменяет текущий вектор. Крайне важно для получения
     *          "чистого" вектора направления.
     */
    void Normalize()
    {
        float length = Length();
        // Защита от деления на ноль, если это нулевой вектор
        if (length > 0.0001f)
        {
            x /= length;
            y /= length;
            z /= length;
        }
    }

    /**
     * @brief Проверяет, является ли вектор нулевым (все компоненты равны 0).
     * @return true, если вектор (0, 0, 0).
     */
    bool isZero() const
    {
        return (x == 0.0f && y == 0.0f && z == 0.0f);
    }
};