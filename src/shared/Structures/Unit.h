#pragma once
#include "WorldObject.h"
#include "shared/Utils/Vector.h"  // Нужен для поля position

#pragma pack(push, 1)

struct CMovement
{
    char unknown_0_to_F[16];
    Vector3 position;
    char padding_1C_to_1F[4];
    float orientation;
    float pitch;
    int field_28;
    float some_coord_or_val_2C;
    int timestamp_or_counter_30;
    char unknown2[16];
    uint32_t movement_flags;
    char padding_48_to_4B[4];
    Vector3 target_pos;
    float target_orientation;
    float target_pitch;
    char unknown_60_to_83[36];
    float fall_start_z_pos;
    float collide_start_z_pos;
    float current_run_speed;
    float walk_back_speed;
    float base_run_speed;
    char unknown_98_to_A3[12];
    float fly_speed;
    char unknown_A8_to_CB[36];
    int mount_type_index;
};

struct AuraIndexEntry
{
    int32_t aura_slot_index;
    int32_t spell_id;
};

/**
 * @struct AuraSlot
 * @brief Полная 24-байтная структура, описывающая одну ауру (бафф или дебафф) на юните.
 */
struct AuraSlot
{
    uint32_t casterGuid_low;
    uint32_t casterGuid_high;
    int32_t spellId;
    uint32_t AuraFlags;
    int32_t duration;

    /**
     * @brief [смещение 0x14] Время окончания ауры, выраженное в "тиках" клиента (результат GetTickCount()).
     * @details Это не оставшееся время! Это метка времени в будущем, когда аура должна закончиться.
     *          Она вычисляется в момент наложения ауры по формуле:
     *          expireTime = startTime (текущий GetTickCount()) + duration.
     * @note Чтобы получить оставшееся время в миллисекундах, нужно использовать формулу:
     *       TimeRemaining = expireTime - GetTickCount().
     *       Это позволяет боту точно знать, когда нужно перекастовать DoT/HoT.
     */
    uint32_t expireTime;
};

/**
 * @struct Unit
 * @brief Расширяет WorldObject, добавляя поля для "живых" существ (NPC, мобы, игроки).
 * @details Наследуется от WorldObject и использует "заполнители" (padding) для
 *          доступа к полям по их точным смещениям в памяти игры.
 */
struct Unit : public WorldObject
{
    // --- Начало: Блок CMovement (детализация твоего старого паддинга) ---
    // WorldObject заканчивается на 0xD0.
    char _pad_after_WoWObject[0x8];    // Доводит до 0xD8
    CMovement* pMovement;              // 0xD8
    char _pad_before_Movement[0x6AC];  // Доводит до 0x788
    CMovement m_movement;              // 0x788, содержит 'position' по смещению +0x10

    // --- Середина: Блок Аур (наши новые находки) ---
    // m_movement заканчивается на 0x788 + 0xD0 = 0x858
    char _pad_before_Auras[0x3F8];  // Доводит до 0xC50
    AuraSlot m_auras[16];           // 0xC50
    int32_t m_auraCount_or_Flag;    // 0xDD0
    char _pad3[0x10C];              // Смещение 0xDD4
    int32_t m_auras_capacity;       // Смещение 0xEE0

    char _pad4[0xAD4];  // Смещение 0xEE4
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
    uint32_t level;

    // Мы не знаем и не объявляем полный размер Unit, так как нам это не нужно.
    // Мы просто объявили "скелет" из тех полей, которые нам интересны.
};

#pragma pack(pop)