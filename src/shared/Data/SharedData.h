#pragma once

// Используем стандартные типы с фиксированным размером для надежности
#include <cstdint>
#include "shared/Utils/Vector.h"

// Максимальное количество объектов, которое мы будем передавать за один раз.
// Это значение должно быть согласовано между DLL и основным приложением.
constexpr int32_t MAX_VISIBLE_OBJECTS = 128;

/**
 * @struct GameObjectInfo
 * @brief Базовая информация об игровом объекте, передаваемая в Shared Memory.
 */
struct GameObjectInfo
{
    /// @brief Уникальный 64-битный идентификатор объекта в игре.
    uint64_t guid = 0;
    /// @brief Тип объекта (игрок, NPC, руда, трава и т.д.).
    uint32_t type = 0;
    /// @brief Позиция объекта в игровом мире.
    Vector3 position;
};

/**
 * @struct PlayerData
 * @brief Структура, описывающая данные о персонаже,
 *        которые DLL будет передавать в основное приложение.
 */
struct PlayerData
{
    /// @brief Текущее здоровье игрока.
    uint32_t health = 0;
    /// @brief Максимальное здоровье игрока.
    uint32_t maxHealth = 0;
    /// @brief Текущая позиция игрока в мире.
    Vector3 position;
};

/**
 * @struct SharedData
 * @brief Главная структура для общей памяти (Shared Memory).
 * @details Это "контракт" данных между DLL и EXE.
 *          Важно, чтобы размер этой структуры был одинаковым в обоих модулях.
 */
struct SharedData
{
    // --- Секция данных (DLL -> EXE) ---
    // DLL будет заполнять эту структуру актуальными данными из игры.

    /// @brief Данные о персонаже игрока.
    PlayerData player;

    /// @brief Количество актуальных объектов в массиве visibleObjects.
    int32_t visibleObjectCount = 0;

    /// @brief Массив с информацией о видимых объектах.
    GameObjectInfo visibleObjects[MAX_VISIBLE_OBJECTS];

    // --- Секция управления (EXE -> DLL) ---
    // В будущем здесь могут быть флаги для управления DLL из EXE.
    // Например: bool shutdown_requested = false;
};