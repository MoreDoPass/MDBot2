#include "WoWController.h"
#include "../shared/Logger.h"
#include <chrono>     // Для работы со временем (std::chrono)
#include <thread>     // для std::this_thread::sleep_for
#include <tlhelp32.h> // <--- Перенесли сюда
#include <windows.h>  // <--- Перенесли сюда

namespace {
std::optional<DWORD> findPidByName(const std::wstring &processName) {
  PROCESSENTRY32W processInfo;
  processInfo.dwSize = sizeof(processInfo);
  HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  if (processesSnapshot == INVALID_HANDLE_VALUE)
    return std::nullopt;
  Process32FirstW(processesSnapshot, &processInfo);
  do {
    if (processName == processInfo.szExeFile) {
      CloseHandle(processesSnapshot);
      return processInfo.th32ProcessID;
    }
  } while (Process32NextW(processesSnapshot, &processInfo));
  CloseHandle(processesSnapshot);
  return std::nullopt;
}
} // namespace

WoWController::WoWController(DWORD pid, uintptr_t playerCoordBaseAddr)
    : m_pid(pid), m_playerCoordBaseAddr(playerCoordBaseAddr) {
  try {
    m_memory = std::make_unique<MemoryReader>(pid);
    qInfo(lcNav) << "WoWController initialized for PID:" << pid;
  } catch (const std::exception &e) {
    qCritical(lcNav) << "Failed to initialize WoWController:" << e.what();
    throw;
  }
}

std::unique_ptr<WoWController>
WoWController::findAndConnect(const std::wstring &processName,
                              uintptr_t playerCoordBaseAddr) {
  auto pidOpt = findPidByName(processName);
  if (!pidOpt) {
    qWarning(lcNav) << "Process" << QString::fromStdWString(processName)
                    << "not found.";
    return nullptr;
  }
  try {
    // Создаем и возвращаем умный указатель
    return std::make_unique<WoWController>(*pidOpt, playerCoordBaseAddr);
  } catch (const std::exception &e) {
    // Конструктор мог выбросить исключение (например, нет прав доступа)
    qCritical(lcNav) << "Failed to connect to process with PID" << *pidOpt
                     << ":" << e.what();
    return nullptr;
  }
}

std::optional<Vector3> WoWController::getPlayerPosition() {
  try {
    Vector3 pos;
    // Вычисляем адреса на лету!
    pos.x = m_memory->readFloat((LPCVOID)m_playerCoordBaseAddr);
    pos.y = m_memory->readFloat((LPCVOID)(m_playerCoordBaseAddr + 4));
    pos.z = m_memory->readFloat((LPCVOID)(m_playerCoordBaseAddr + 8));
    return pos;
  } catch (const std::exception &e) {
    qWarning(lcNav) << "Failed to get player position:" << e.what();
    return std::nullopt;
  }
}

DWORD WoWController::getPid() const { return m_pid; }
uintptr_t WoWController::getBaseAddress() const {
  return m_playerCoordBaseAddr;
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