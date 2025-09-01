#pragma once
#include <cstdint>
#include "Enums/GameObjectType.h"

#pragma pack(push, 1)

/**
 * @struct WorldObject
 * @brief Полное представление структуры WorldObject, основанное на реверс-инжиниринге.
 */
struct WorldObject
{
    // --- Смещение 0x00 ---
    void* vtable;

    // --- Смещение 0x04 ---
    uint32_t unknown_0x04;

    // --- Смещение 0x08 ---
    void* pGuid;  // Указатель, 4 байта
    void* pId;    // Указатель, 4 байта

    // --- Смещение 0x10 ---
    uint32_t unknown_0x10;

    // --- Смещение 0x14 ---
    GameObjectType objectType;

    // --- Смещение 0x18 ---
    uint32_t guid_low_part;
    void* hashTable_pNext;
    void* hashTable_pPrev;
    void* globalList_pNext;
    void* globalList_pPrev;
    uint32_t unknown_0x2C;

    // --- Смещение 0x30 ---
    uint64_t guid;

    // --- Смещение 0x38 ---
    void* ownedList_pFirst;
    void* ownedList_pLast;
    void* pOwnerObject;
    uint32_t padding_0x44;
    void* ownedList2_pFirst;
    void* ownedList2_pLast;
    uint32_t padding_0x50;

    // --- Смещение 0x54 ---
    char unknown_data_remaining[124];
};

#pragma pack(pop)

// Наша святая страховка
static_assert(sizeof(WorldObject) == 0xD0, "Size of WorldObject is incorrect!");