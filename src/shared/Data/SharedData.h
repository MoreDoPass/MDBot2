#pragma once
#include <cstdint>
#include "shared/Utils/Vector.h"
#include "shared/Structures/Enums/GameObjectType.h"  // Включаем наш enum

constexpr int32_t MAX_VISIBLE_OBJECTS = 128;

/**
 * @struct GameObjectInfo
 * @brief "Плоская" структура для передачи полной информации об объекте через Shared Memory.
 * @details Содержит все часто используемые поля, прочитанные DLL из памяти игры.
 */
struct GameObjectInfo
{
    // --- Базовые данные, есть у всех ---
    uint64_t guid = 0;
    uintptr_t baseAddress = 0;  // Указатель на объект в памяти игры
    GameObjectType type = GameObjectType::None;
    Vector3 position;

    // --- Данные для Unit/Player ---
    uint32_t health = 0;
    uint32_t maxHealth = 0;
    uint32_t mana = 0;
    uint32_t maxMana = 0;
    uint8_t level = 0;

    // --- Данные для GameObject (руда/трава) ---
    // Пока оставим пустым, добавим позже при необходимости (например, имя)
};

/**
 * @struct PlayerData
 * @brief Данные о персонаже игрока.
 */
struct PlayerData
{
    uint32_t health = 0;
    uint32_t maxHealth = 0;
    Vector3 position;
};

/**
 * @struct SharedData
 * @brief Главная структура для общей памяти (Shared Memory).
 */
struct SharedData
{
    PlayerData player;
    int32_t visibleObjectCount = 0;
    GameObjectInfo visibleObjects[MAX_VISIBLE_OBJECTS];
};