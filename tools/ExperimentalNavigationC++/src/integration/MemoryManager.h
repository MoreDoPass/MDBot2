#pragma once

#include <stdexcept> // Для стандартных исключений (std::runtime_error)
#include <string>    // Для std::string
#include <windows.h> // Главный заголовочный файл для Windows API


/**
 * @class MemoryReader
 * @brief Предоставляет низкоуровневый интерфейс для чтения и записи в память
 * другого процесса.
 * @details Использует функции Windows API (Kernel32.dll), такие как
 * OpenProcess, ReadProcessMemory и WriteProcessMemory. Реализует идиому RAII:
 *          handle процесса открывается в конструкторе и автоматически
 * закрывается в деструкторе.
 */
class MemoryReader {
public:
  /**
   * @brief Конструктор, открывающий handle для указанного процесса.
   * @param pid Process ID (PID) целевого процесса.
   * @throws std::runtime_error если не удалось получить доступ к процессу.
   */
  explicit MemoryReader(DWORD pid);

  /**
   * @brief Деструктор, автоматически закрывающий handle процесса.
   */
  ~MemoryReader();

  // Запрещаем копирование и присваивание, т.к. handle уникален
  MemoryReader(const MemoryReader &) = delete;
  MemoryReader &operator=(const MemoryReader &) = delete;

  /**
   * @brief Читает 4-байтное float значение из памяти.
   * @param address Адрес в памяти целевого процесса.
   * @return Прочитанное значение.
   * @throws std::runtime_error если чтение не удалось.
   */
  float readFloat(LPCVOID address) const;

  /**
   * @brief Записывает 4-байтное float значение в память.
   * @param address Адрес для записи.
   * @param value Значение для записи.
   * @throws std::runtime_error если запись не удалась.
   */
  void writeFloat(LPVOID address, float value);

  /**
   * @brief Записывает 4-байтное int значение в память.
   * @param address Адрес для записи.
   * @param value Значение для записи.
   * @throws std::runtime_error если запись не удалась.
   */
  void writeInt(LPVOID address, int32_t value);

private:
  /// @brief Handle целевого процесса.
  HANDLE m_processHandle = NULL;
};