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
    int32_t entryId = 0;
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
 * @enum ClientCommandType
 * @brief Перечисление типов команд, которые основное приложение (клиент) может отправить в DLL.
 */
enum class ClientCommandType : uint32_t
{
    None = 0,  ///< Нет команды, состояние по умолчанию.
    MoveTo,    ///< Команда на перемещение к указанным координатам.
    Interact,  ///< Команда на взаимодействие с целью (NPC, руда, трава).
    Attack,    ///< Команда на атаку цели.
    Stop       ///< Команда на прекращение текущего действия.
};

/**
 * @struct ClientCommand
 * @brief Структура для передачи одной команды от клиента в DLL.
 */
struct ClientCommand
{
    /// @brief Тип выполняемой команды. DLL сбросит его в None после выполнения.
    ClientCommandType type = ClientCommandType::None;

    /// @brief Координаты для команды MoveTo.
    Vector3 position;

    /// @brief GUID цели для команд Interact или Attack.
    uint64_t targetGuid = 0;
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

    ClientCommand commandToDll;
};