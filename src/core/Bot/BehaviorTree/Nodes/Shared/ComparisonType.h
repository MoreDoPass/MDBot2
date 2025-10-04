#pragma once

/**
 * @enum ComparisonType
 * @brief Определяет, какой тип математического сравнения будет выполнять узел.
 * @details Этот enum является общим (shared) и используется во всех узлах-условиях,
 *          которым необходимо сравнивать значения (уровень, здоровье, мана и т.д.).
 */
enum class ComparisonType
{
    GreaterOrEqual,  // >=
    Less,            // <
    Equal,           // ==
    Greater,         // >
    LessOrEqual      // <=
};