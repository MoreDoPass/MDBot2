#pragma once

#include <cmath>
#include <iostream>

/**
 * @class Vector3
 * @brief Простой класс для работы с 3D векторами.
 *
 * Используется для представления координат в мире WoW и Recast.
 * Поддерживает основные математические операции.
 */
class Vector3
{
   public:
    float x, y, z;

    /**
     * @brief Конструктор по умолчанию.
     */
    Vector3() : x(0.0f), y(0.0f), z(0.0f) {}

    /**
     * @brief Конструктор с параметрами.
     * @param x_ Координата X
     * @param y_ Координата Y
     * @param z_ Координата Z
     */
    Vector3(float x_, float y_, float z_) : x(x_), y(y_), z(z_) {}

    /**
     * @brief Оператор сложения векторов.
     * @param other Вектор для сложения
     * @return Результат сложения
     */
    Vector3 operator+(const Vector3& other) const
    {
        return Vector3(x + other.x, y + other.y, z + other.z);
    }

    /**
     * @brief Оператор вычитания векторов.
     * @param other Вектор для вычитания
     * @return Результат вычитания
     */
    Vector3 operator-(const Vector3& other) const
    {
        return Vector3(x - other.x, y - other.y, z - other.z);
    }

    /**
     * @brief Оператор умножения на скаляр.
     * @param scalar Скаляр для умножения
     * @return Результат умножения
     */
    Vector3 operator*(float scalar) const
    {
        return Vector3(x * scalar, y * scalar, z * scalar);
    }

    /**
     * @brief Оператор деления на скаляр.
     * @param scalar Скаляр для деления
     * @return Результат деления
     */
    Vector3 operator/(float scalar) const
    {
        if (std::abs(scalar) < 1e-6f)
        {
            return Vector3();
        }
        return Vector3(x / scalar, y / scalar, z / scalar);
    }

    /**
     * @brief Оператор присваивания сложения.
     * @param other Вектор для сложения
     * @return Ссылка на текущий объект
     */
    Vector3& operator+=(const Vector3& other)
    {
        x += other.x;
        y += other.y;
        z += other.z;
        return *this;
    }

    /**
     * @brief Оператор присваивания вычитания.
     * @param other Вектор для вычитания
     * @return Ссылка на текущий объект
     */
    Vector3& operator-=(const Vector3& other)
    {
        x -= other.x;
        y -= other.y;
        z -= other.z;
        return *this;
    }

    /**
     * @brief Оператор сравнения на равенство.
     * @param other Вектор для сравнения
     * @return true если векторы равны
     */
    bool operator==(const Vector3& other) const
    {
        const float epsilon = 1e-6f;
        return std::abs(x - other.x) < epsilon && std::abs(y - other.y) < epsilon && std::abs(z - other.z) < epsilon;
    }

    /**
     * @brief Оператор сравнения на неравенство.
     * @param other Вектор для сравнения
     * @return true если векторы не равны
     */
    bool operator!=(const Vector3& other) const
    {
        return !(*this == other);
    }

    /**
     * @brief Вычисляет длину вектора.
     * @return Длина вектора
     */
    float length() const
    {
        return std::sqrt(x * x + y * y + z * z);
    }

    /**
     * @brief Вычисляет квадрат длины вектора (оптимизация).
     * @return Квадрат длины вектора
     */
    float lengthSquared() const
    {
        return x * x + y * y + z * z;
    }

    /**
     * @brief Нормализует вектор (делает длину равной 1).
     * @return Нормализованный вектор
     */
    Vector3 normalized() const
    {
        float len = length();
        if (len < 1e-6f)
        {
            return Vector3();
        }
        return *this / len;
    }

    /**
     * @brief Вычисляет расстояние до другого вектора.
     * @param other Целевой вектор
     * @return Расстояние между векторами
     */
    float distanceTo(const Vector3& other) const
    {
        return (*this - other).length();
    }

    /**
     * @brief Вычисляет квадрат расстояния до другого вектора (оптимизация).
     * @param other Целевой вектор
     * @return Квадрат расстояния между векторами
     */
    float distanceSquaredTo(const Vector3& other) const
    {
        return (*this - other).lengthSquared();
    }

    /**
     * @brief Проверяет, является ли вектор нулевым.
     * @return true если вектор нулевой
     */
    bool isZero() const
    {
        const float epsilon = 1e-6f;
        return std::abs(x) < epsilon && std::abs(y) < epsilon && std::abs(z) < epsilon;
    }

    /**
     * @brief Выводит вектор в поток.
     * @param os Поток вывода
     * @param vec Вектор для вывода
     * @return Поток вывода
     */
    friend std::ostream& operator<<(std::ostream& os, const Vector3& vec)
    {
        os << "(" << vec.x << ", " << vec.y << ", " << vec.z << ")";
        return os;
    }

    // В файле Vector.h, внутри класса Vector3

    /**
     * @brief Вычисляет евклидово расстояние до другой точки.
     * @param other Другая точка.
     * @return Расстояние между точками.
     */
    float distance(const Vector3& other) const
    {
        float dx = x - other.x;
        float dy = y - other.y;
        float dz = z - other.z;
        return std::sqrt(dx * dx + dy * dy + dz * dz);
    }
};