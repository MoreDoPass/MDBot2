#pragma once
#include <cstdint>
#include "shared/Utils/Vector.h"
#include "shared/Structures/Enums/GameObjectType.h"  // Включаем наш enum

constexpr int32_t MAX_VISIBLE_OBJECTS = 128;
constexpr int32_t MAX_AURAS_PER_UNIT = 40;
constexpr int32_t MAX_PLAYER_COOLDOWNS = 32;

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

    /**
     * @brief Горизонтальный угол поворота юнита в радианах.
     * @details Критически важно для определения, куда смотрит цель (для атак со спины)
     *          и куда смотрим мы (для проверки facing).
     */
    float orientation = 0.0f;  // <-- ДОБАВЛЯЕМ СЮДА

    // --- Данные для Unit/Player ---
    uint32_t health = 0;
    uint32_t maxHealth = 0;
    uint32_t mana = 0;
    uint32_t maxMana = 0;
    uint8_t level = 0;
    uint32_t flags = 0;
    uint64_t targetGuid = 0;

    int32_t auraCount;
    int32_t auras[MAX_AURAS_PER_UNIT];

    bool isCasting;
    uint32_t castingSpellId;
};

/**
 * @struct SpellCooldown
 * @brief "Плоская" структура для передачи информации об одном активном кулдауне.
 */
struct SpellCooldown
{
    uint32_t spellId;
    uint32_t startTime;
    uint32_t duration;
    // Мы не передаем categoryCooldown и другие сложные поля,
    // так как боту для принятия решения достаточно знать, активен ли КД по spellId.
};

/**
 * @struct PlayerData
 * @brief Детальная информация о персонаже игрока.
 * @details Эта структура заполняется в DLL и читается классом Character в основном приложении.
 */
struct PlayerData
{
    // --- Базовые данные ---
    uint64_t guid = 0;
    uintptr_t baseAddress = 0;  ///< Указатель на структуру игрока, нужен для телепортации.
    Vector3 position;

    // --- Основные статы ---
    uint32_t health = 0;
    uint32_t maxHealth = 0;
    uint32_t mana = 0;
    uint32_t maxMana = 0;
    uint8_t level = 0;
    uint32_t flags = 0;

    // --- ДОБАВЛЯЕМ БЛОК ДЛЯ КУЛДАУНОВ ---
    int32_t activeCooldownCount = 0;
    SpellCooldown activeCooldowns[MAX_PLAYER_COOLDOWNS];

    /**
     * @brief Флаг, указывающий, активен ли в данный момент боевой ГКД.
     * @details Заполняется функцией ReadPlayerCooldowns. Если true, бот не должен
     *          пытаться использовать способности, подверженные ГКД.
     */
    bool isGcdActive;
};

// Этот enum используется и "мозгом", и DLL.
enum class CommandStatus : uint32_t
{
    None,         // Нет команды, ничего не делать.
    Pending,      // "Мозг" выставил новую команду, DLL должна ее выполнить.
    Acknowledged  // DLL выполнила команду и ждет, пока "мозг" это увидит и очистит.
};

/**
 * @enum ClientCommandType
 * @brief Перечисление типов команд, которые основное приложение (клиент) может отправить в DLL.
 */
enum class ClientCommandType : uint32_t
{
    None = 0,  ///< Нет команды, состояние по умолчанию.
    MoveTo,    ///< Команда на перемещение к указанным координатам.
    Attack,    ///< Команда на атаку цели.
    Stop,      ///< Команда на прекращение текущего действия.

    // Теперь "Мозг" может приказать "Агенту" кастовать заклинание на цель.
    CastSpellOnTarget,

    /**
     * @brief Команда на поворот персонажа лицом к цели.
     * @details Использует внутриигровой механизм Click-To-Move.
     *          В качестве параметра используется targetGuid.
     */
    FaceTarget,
    NativeInteract
};

/**
 * @struct ClientCommand
 * @brief Структура для передачи одной команды от клиента в DLL.
 */
struct ClientCommand
{
    /// @brief Тип выполняемой команды. DLL сбросит его в None после выполнения.
    ClientCommandType type = ClientCommandType::None;

    /// А вот это поле будет управлять жизненным циклом команды
    CommandStatus status = CommandStatus::None;

    /// @brief Координаты для команды MoveTo.
    Vector3 position;

    /// @brief GUID цели для команд Interact или Attack.
    uint64_t targetGuid = 0;

    // Добавляем новое поле в "бланк заказа".
    // Теперь, когда мы отдаем приказ CastSpellOnTarget,
    // мы можем указать в этом поле ID нужного заклинания.
    int32_t spellId = 0;
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