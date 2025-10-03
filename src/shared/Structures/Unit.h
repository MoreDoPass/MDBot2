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
 * @struct UnitProperties
 * @brief Хранит основные динамические характеристики и состояния юнита.
 * @details Доступ к этому блоку данных осуществляется через указатель pUnitProperties
 *          в объекте Unit. Это позволяет унифицировать доступ к состоянию как для
 *          игроков (Player), так и для NPC (Unit), несмотря на различия в их
 *          базовых структурах памяти.
 */
struct UnitProperties  // sizeof=0xD8
{
    char _pad0[48];
    unsigned int targetGuid_low;
    unsigned int targetGuid_high;
    char _pad_to_health[16];
    unsigned int currentHealth;
    unsigned int currentMana;
    unsigned int currentRage;  ///< Хранится *10 (100 силы рун = 1000)
    unsigned int dunno_field;
    unsigned int currentEnergy;
    char _pad_power_block[8];
    unsigned int currentRunicPower;  ///< Хранится *10 (100 силы рун = 1000)
    unsigned int maxHealth;
    unsigned int maxMana;
    char _pad2[80];
    unsigned int level;
    char _pad3[16];

    /**
     * @brief [смещение 0xD4] Битовое поле, хранящее различные состояния юнита.
     * @details Каждый бит отвечает за определенный флаг (в бою, на маунте, мертв и т.д.).
     *          Для проверки состояния используется побитовая операция 'И' (&).
     *          Если результат не равен нулю, флаг установлен.
     *
     *          Ключевой флаг:
     *          - **Флаг боя:** находится в 19-м бите (маска 0x80000).
     *
     * @code
     * // Пример проверки, находится ли юнит в бою:
     * if (pUnit->pUnitProperties->flags & 0x80000)
     * {
     *     // Юнит в бою
     * }
     * @endcode
     */
    unsigned int flags;
    char padding_0xD8[24];

    /**
     * @brief [смещение 0xF0] Игровой радиус модели.
     * @details Это значение напрямую влияет на максимальное расстояние, с которого юнит
     *          может атаковать или быть атакован. Оно добавляется
     *          к базовой дистанции атаки вместе с радиусом цели.
     *          Формула: Макс. дистанция = Базовая дист. + combatReach (атакующего) + combatReach (цели).
     *
     * @code
     * // Пример расчета реальной дистанции атаки:
     * const float BASE_MELEE_RANGE = 5.0f;
     * float playerReach = pPlayer->pUnitProperties->combatReachRadius;
     * float targetReach = pTarget->pUnitProperties->combatReachRadius;
     * float maxAttackRange = BASE_MELEE_RANGE + playerReach + targetReach;
     *
     * if (distanceToTarget <= maxAttackRange)
     * {
     *     // Цель в радиусе атаки
     * }
     * @endcode
     */
    float combatReachRadius;

    char padding_0xF4[48];

    /**
     * @brief [смещение 0x124] Битовое поле, отвечающее за состояние "занятости" (tap) юнита.
     * @details Ключевой флаг здесь - это 3-й бит (маска 0x4), который устанавливается,
     *          когда юнит "занят" другим игроком, не состоящим в вашей группе.
     *          Это основной и самый надежный признак "серого" моба. Если этот флаг
     *          равен 0, моб либо свободен, либо занят вами или вашей группой.
     *
     * @code
     * // Пример проверки, является ли моб "серым" (бесполезным для атаки):
     * if (pUnit->pUnitProperties->tapFlags & 0x4)
     * {
     *     // Моб "серый", атаковать бессмысленно.
     * }
     * @endcode
     */
    unsigned int tapFlags;
};

/**
 * @struct Unit
 * @brief Расширяет WorldObject, добавляя поля для "живых" существ (NPC, мобы, игроки).
 * @details Наследуется от WorldObject и использует "заполнители" (padding) для
 *          доступа к полям по их точным смещениям в памяти игры.
 */
struct Unit : public WorldObject
{
    UnitProperties* pUnitProperties;
    char _pad_after_WoWObject[0x4];    // Доводит до 0xD8
    CMovement* pMovement;              // 0xD8
    char _pad_before_Movement[0x6AC];  // Доводит до 0x788
    CMovement m_movement;              // 0x788, содержит 'position' по смещению +0x10
    char padding_to_autoAttackTarget[456];

    /**
     * @brief [смещение 0xA20] 64-битный GUID цели, на которую в данный момент направлена автоатака.
     * @details Это поле является главным индикатором состояния автоатаки.
     *          - Если значение равно 0, автоатака неактивна.
     *          - Если значение отлично от 0, оно содержит GUID юнита, который является текущей
     *            целью автоматических атак ближнего боя.
     *          Поле обновляется клиентом в момент отправки на сервер пакета CMSG_ATTACKSWING.
     *
     * @note Поле разделено на две 32-битные части для совместимости с 32-битной архитектурой.
     */
    uint32_t autoAttackTargetGuid_low;
    uint32_t autoAttackTargetGuid_high;

    char padding_after_autoAttackTarget[52];
    uint8_t castID;  // 0xA5C
    char padding_A5D[15];
    uint32_t castSpellId;
    uint32_t castTargetGuid_low;
    uint32_t castTargetGuid_high;
    uint32_t castStartTime;
    uint32_t castEndTime;
    char padding_A80[464];

    AuraSlot m_auras[16];         // 0xC50
    int32_t m_auraCount_or_Flag;  // 0xDD0
    char _pad3[0x10C];            // Смещение 0xDD4
    int32_t m_auras_capacity;     // Смещение 0xEE0
};

#pragma pack(pop)