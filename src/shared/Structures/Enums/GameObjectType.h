#pragma once
#include <cstdint>

/**
 * @enum GameObjectType
 * @brief Перечисление базовых типов игровых объектов.
 * @details Значения основаны на данных клиента 3.3.5a.
 */
enum class GameObjectType : uint32_t
{
    None = 0,
    Item = 1,
    Container = 2,
    Unit = 3,           // NPC, мобы, криттеры
    Player = 4,         // Игроки
    GameObject = 5,     // Руда, трава, сундуки
    DynamicObject = 6,  // "Динамические" объекты, вроде огня от заклинания
    Corpse = 7          // Тела
};