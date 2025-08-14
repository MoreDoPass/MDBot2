#include "MemoryManager.h"
#include "shared/Logger.h" // Подключим логгер для диагностики

MemoryReader::MemoryReader(DWORD pid) {
  // Открываем процесс для чтения, записи и операций с памятью.
  m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (m_processHandle == NULL) {
    // Если не удалось, бросаем исключение с кодом ошибки Windows
    throw std::runtime_error("Failed to open process. Error code: " +
                             std::to_string(GetLastError()));
  }
  qInfo(lcNav) << "Successfully opened handle to process with PID:" << pid;
}

MemoryReader::~MemoryReader() {
  if (m_processHandle != NULL) {
    CloseHandle(m_processHandle);
    qInfo(lcNav) << "Process handle closed.";
  }
}

float MemoryReader::readFloat(LPCVOID address) const {
  float buffer = 0.0f;
  SIZE_T bytesRead = 0;

  // Вызываем функцию WinAPI для чтения памяти
  if (!ReadProcessMemory(m_processHandle, address, &buffer, sizeof(buffer),
                         &bytesRead) ||
      bytesRead != sizeof(buffer)) {
    throw std::runtime_error("Failed to read float from address " +
                             std::to_string((uintptr_t)address) +
                             ". Error code: " + std::to_string(GetLastError()));
  }
  return buffer;
}

void MemoryReader::writeFloat(LPVOID address, float value) {
  SIZE_T bytesWritten = 0;
  if (!WriteProcessMemory(m_processHandle, address, &value, sizeof(value),
                          &bytesWritten) ||
      bytesWritten != sizeof(value)) {
    throw std::runtime_error("Failed to write float to address " +
                             std::to_string((uintptr_t)address) +
                             ". Error code: " + std::to_string(GetLastError()));
  }
}

void MemoryReader::writeInt(LPVOID address, int32_t value) {
  SIZE_T bytesWritten = 0;
  if (!WriteProcessMemory(m_processHandle, address, &value, sizeof(value),
                          &bytesWritten) ||
      bytesWritten != sizeof(value)) {
    throw std::runtime_error("Failed to write int to address " +
                             std::to_string((uintptr_t)address) +
                             ". Error code: " + std::to_string(GetLastError()));
  }
}