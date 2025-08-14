#include "WoWController.h"
#include "../shared/Logger.h"
#include <chrono> // Для работы со временем (std::chrono)
#include <thread> // для std::this_thread::sleep_for

WoWController::WoWController(DWORD pid, uintptr_t playerXAddr,
                             uintptr_t playerYAddr, uintptr_t playerZAddr)
    : m_playerXAddr(playerXAddr), m_playerYAddr(playerYAddr),
      m_playerZAddr(playerZAddr) {
  // Создаем экземпляр MemoryReader. Если OpenProcess не удастся,
  // конструктор MemoryReader бросит исключение.
  try {
    m_memory = std::make_unique<MemoryReader>(pid);
    qInfo(lcNav) << "WoWController initialized.";
  } catch (const std::exception &e) {
    qCritical(lcNav) << "Failed to initialize WoWController:" << e.what();
    // Перебрасываем исключение дальше, чтобы создатель объекта знал об ошибке
    throw;
  }
}

std::optional<Vector3> WoWController::getPlayerPosition() {
  try {
    Vector3 pos;
    // Заметь, мы используем (LPCVOID) для приведения типа, как того требует
    // функция
    pos.x = m_memory->readFloat((LPCVOID)m_playerXAddr);
    pos.y = m_memory->readFloat((LPCVOID)m_playerYAddr);
    pos.z = m_memory->readFloat((LPCVOID)m_playerZAddr);
    return pos;
  } catch (const std::exception &e) {
    qWarning(lcNav) << "Failed to get player position:" << e.what();
    return std::nullopt; // Возвращаем "пустое" значение
  }
}

void WoWController::executeMove(const Vector3 &target, float distance) {
  try {
    // (LPVOID) - приведение типа к указателю, которого ожидает функция
    m_memory->writeFloat((LPVOID)CTM_X_COORD, target.x);
    m_memory->writeFloat((LPVOID)CTM_Y_COORD, target.y);
    m_memory->writeFloat((LPVOID)CTM_Z_COORD, target.z);
    m_memory->writeFloat((LPVOID)CTM_DISTANCE, distance);
    m_memory->writeInt((LPVOID)CTM_ACTION_TYPE,
                       static_cast<int32_t>(ActionType::MoveTo));
  } catch (const std::exception &e) {
    qCritical(lcNav) << "Failed to execute CTM move:" << e.what();
  }
}

void WoWController::followPath(const std::vector<Vector3> &pathWaypoints,
                               float arrivalThreshold, float stuckTimeout) {
  if (pathWaypoints.empty()) {
    qInfo(lcNav) << "Path is empty, no movement required.";
    return;
  }

  qInfo(lcNav) << "Starting to follow path with" << pathWaypoints.size()
               << "waypoints.";

  for (size_t i = 0; i < pathWaypoints.size(); ++i) {
    const auto &waypoint = pathWaypoints[i];
    qInfo(lcNav) << "Moving to waypoint" << (i + 1) << "at" << waypoint.x
                 << waypoint.y << waypoint.z;
    executeMove(waypoint);

    auto startTime = std::chrono::steady_clock::now();
    while (true) {
      // Проверка на "застревание"
      auto now = std::chrono::steady_clock::now();
      std::chrono::duration<float> elapsed = now - startTime;
      if (elapsed.count() > stuckTimeout) {
        qWarning(lcNav) << "Stuck timeout reached for waypoint" << (i + 1)
                        << ". Moving to the next one.";
        break;
      }

      // Проверка позиции
      auto currentPosOpt = getPlayerPosition();
      if (!currentPosOpt) {
        qCritical(lcNav)
            << "Lost access to player coordinates. Aborting path following.";
        return;
      }

      const auto &currentPos = *currentPosOpt;
      float dx = currentPos.x - waypoint.x;
      float dy = currentPos.y - waypoint.y;
      float distanceSq =
          dx * dx + dy * dy; // Сравниваем квадраты расстояний, это быстрее

      if (distanceSq < (arrivalThreshold * arrivalThreshold)) {
        qInfo(lcNav) << "Waypoint" << (i + 1) << "reached.";
        break;
      }

      std::this_thread::sleep_for(
          std::chrono::milliseconds(100)); // Пауза, чтобы не грузить ЦП
    }
  }
  qInfo(lcNav) << "Path following finished.";
}