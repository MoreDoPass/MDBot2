#pragma once

#include "core/Utils/Vector.h"
#include <cstdint>

/**
 * @brief Перечисление базовых типов игровых объектов.
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

#pragma pack(push, 1)  // Отключаем выравнивание

/**
 * @struct GameObject
 * @brief Самая базовая структура, от которой наследуются все остальные.
 */
struct GameObject
{
    /// @brief [смещение 0x00] Пропускаем неизвестные байты до поля 'type'.
    char _pad0[0x14];

    /// @brief [смещение 0x14, размер 4] Тип этого игрового объекта.
    GameObjectType type;

    /// @brief [смещение 0x18] Пропускаем неизвестные байты до поля 'guid'.
    char _pad1[0x30 - (0x14 + sizeof(type))];

    /// @brief [смещение 0x30, размер 8] Уникальный 64-битный идентификатор объекта.
    uint64_t guid;

    /// @brief [смещение 0x38] Пропускаем неизвестные байты до поля 'position'.
    char _pad2[0x798 - (0x30 + sizeof(guid))];

    /// @brief [смещение 0x798, размер 12] Позиция объекта в 3D мире (X, Y, Z).
    Vector3 position;

    // Все, что после 0x798 + 12 = 0x7A4, нас пока не интересует.
    // Если понадобится поле с бОльшим смещением, мы добавим еще один заполнитель.
};

#pragma pack(pop)  // Включаем выравнивание обратно