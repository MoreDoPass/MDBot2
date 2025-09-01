#pragma once
#include "WorldObject.h"
#include "shared/Utils/Vector.h"  // Нужен для поля position

#pragma pack(push, 1)

/**
 * @struct Unit
 * @brief Расширяет WorldObject, добавляя поля для "живых" существ (NPC, мобы, игроки).
 * @details Наследуется от WorldObject и использует "заполнители" (padding) для
 *          доступа к полям по их точным смещениям в памяти игры.
 */
struct Unit : public WorldObject
{
    // C++ автоматически разместил здесь WorldObject размером 0xD0 байт.
    // Теперь мы "дотягиваемся" до полей, специфичных для Unit.

    // 1. Заполнитель от конца WorldObject (0xD0) до поля position (0x798)
    char _pad_to_position[0x798 - sizeof(WorldObject)];

    /// @brief [смещение 0x798] Позиция объекта в 3D мире (X, Y, Z).
    Vector3 position;

    // 2. Заполнитель от конца position (0x798 + 0xC = 0x7A4) до поля health (0x19B8)
    char _pad_to_health[0x19B8 - (0x798 + sizeof(Vector3))];

    /// @brief [смещение 0x19B8] Текущее здоровье.
    uint32_t health;

    /// @brief [смещение 0x19BC] Текущая мана/энергия/ярость.
    uint32_t mana;

    // 3. Заполнитель от конца mana (0x19BC + 4 = 0x19C0) до поля maxHealth (0x19D8)
    char _pad_to_maxHealth[0x19D8 - (0x19BC + sizeof(mana))];

    /// @brief [смещение 0x19D8] Максимальное здоровье.
    uint32_t maxHealth;

    /// @brief [смещение 0x19DC] Максимальная мана/энергия/ярость.
    uint32_t maxMana;

    // 4. Заполнитель от конца maxMana (0x19DC + 4 = 0x19E0) до поля level (0x1A30)
    char _pad_to_level[0x1A30 - (0x19DC + sizeof(maxMana))];

    /// @brief [смещение 0x1A30] Уровень юнита.
    uint8_t level;

    // Мы не знаем и не объявляем полный размер Unit, так как нам это не нужно.
    // Мы просто объявили "скелет" из тех полей, которые нам интересны.
};

#pragma pack(pop)