#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <QLoggingCategory>

/**
 * @brief Структура с информацией о процессе.
 */
struct ProcessInfo
{
    uint32_t pid;       ///< Идентификатор процесса
    std::wstring name;  ///< Имя процесса
};

Q_DECLARE_LOGGING_CATEGORY(processManagerLog)

/**
 * @brief Класс для поиска процессов по имени.
 * @details Использует WinAPI для поиска процессов. Только статические методы.
 */
class ProcessManager
{
   public:
    /**
     * @brief Найти все процессы с заданным именем.
     * @param processName Имя процесса (например, L"run.exe")
     * @return Вектор структур ProcessInfo
     */
    static std::vector<ProcessInfo> findProcessesByName(const std::wstring& processName);

   private:
    ProcessManager() = delete;  ///< Запретить создание экземпляра
};
