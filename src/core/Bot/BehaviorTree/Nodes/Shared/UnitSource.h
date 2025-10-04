#pragma once

/**
 * @enum UnitSource
 * @brief Указывает, откуда узел Дерева Поведения должен взять GUID юнита для проверки.
 *        Это "символическое имя" для юнита, которое разрешается (превращается в реальный GUID)
 *        во время выполнения tick() узла.
 */
enum class UnitSource
{
    Self,           // Взять GUID нашего персонажа из context.character
    CurrentTarget,  // Взять GUID текущей цели из context.currentTargetGuid
};