#pragma once

#include "MemoryManager.h"
#include <cstdint>  // Для целочисленных типов вроде int32_t
#include <memory>   // Для std::unique_ptr
#include <optional> // Для представления опциональных значений
#include <vector>   // Для std::vector

// Создадим простую структуру для 3D координат, чтобы не тащить сюда Eigen
struct Vector3 {
  float x, y, z;
};

/**
 * @class WoWController
 * @brief Управляет взаимодействием с процессом игры (чтение координат, CTM).
 */
class WoWController {
public:
  /**
   * @brief Типы действий для функции ClickToMove.
   */
  enum class ActionType : int32_t {
    MoveTo = 4,
    // ... другие типы можно добавить сюда
  };

  /**
   * @brief Конструктор.
   * @param pid Process ID процесса игры.
   * @param playerXAddr Адрес координаты X.
   * @param playerYAddr Адрес координаты Y.
   * @param playerZAddr Адрес координаты Z.
   */
  WoWController(DWORD pid, uintptr_t playerXAddr, uintptr_t playerYAddr,
                uintptr_t playerZAddr);

  /**
   * @brief Получает текущую позицию игрока.
   * @return std::optional<Vector3> Координаты игрока, или std::nullopt в случае
   * ошибки.
   */
  std::optional<Vector3> getPlayerPosition();

  /**
   * @brief Ведет персонажа по заданному пути.
   * @param pathWaypoints Вектор точек пути в мировых координатах.
   * @param arrivalThreshold Дистанция до точки, считающаяся ее достижением.
   * @param stuckTimeout Время в секундах, после которого движение к точке
   * прерывается.
   */
  void followPath(const std::vector<Vector3> &pathWaypoints,
                  float arrivalThreshold = 2.5f, float stuckTimeout = 30.0f);

private:
  /**
   * @brief Записывает команду на движение в память.
   */
  void executeMove(const Vector3 &target, float distance = 0.3f);

  /// @brief Умный указатель на наш объект для работы с памятью.
  std::unique_ptr<MemoryReader> m_memory;

  // --- Динамические адреса игрока ---
  uintptr_t m_playerXAddr;
  uintptr_t m_playerYAddr;
  uintptr_t m_playerZAddr;

  // --- Статические адреса для CTM ---
  const uintptr_t CTM_DISTANCE = 0xCA11E4;
  const uintptr_t CTM_ACTION_TYPE = 0xCA11F4;
  const uintptr_t CTM_X_COORD = 0xCA1264;
  const uintptr_t CTM_Y_COORD = 0xCA1268;
  const uintptr_t CTM_Z_COORD = 0xCA126C;
};