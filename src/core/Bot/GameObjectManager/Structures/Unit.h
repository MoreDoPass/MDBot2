#pragma once

#include "GameObject.h"

#pragma pack(push, 1)

/**
 * @struct Unit
 * @brief Структура для всех "живых" существ (NPC, мобы, игроки).
 * @details Наследуется от GameObject и добавляет поля, связанные со здоровьем, маной и т.д.
 */
struct Unit : public GameObject
{
    // C++ автоматически разместит поля GameObject (до смещения 0x7A4) в начале этой структуры.
    // Теперь мы добавляем "заполнитель" от конца GameObject до первого нужного нам поля Unit (health at 0x19B8).

    /// @brief Пропускаем байты от конца GameObject до поля 'health'.
    char _pad_unit_1[0x19B8 - sizeof(GameObject)];

    /// @brief [смещение 0x19B8, размер 4] Текущее здоровье.
    uint32_t health;

    /// @brief [смещение 0x19BC, размер 4] Текущая мана/энергия/ярость.
    uint32_t mana;

    // Промежуток между mana и maxHealth (0x19D8 - (0x19BC + 4))
    char _pad_unit_2[0x19D8 - (0x19BC + sizeof(mana))];

    /// @brief [смещение 0x19D8, размер 4] Максимальное здоровье.
    uint32_t maxHealth;

    /// @brief [смещение 0x19DC, размер 4] Максимальная мана/энергия/ярость.
    uint32_t maxMana;

    // Промежуток между maxMana и level (0x1A30 - (0x19DC + 4))
    char _pad_unit_3[0x1A30 - (0x19DC + sizeof(maxMana))];

    /// @brief [смещение 0x1A30, размер 1] Уровень юнита.
    uint8_t level;
};

#pragma pack(pop)