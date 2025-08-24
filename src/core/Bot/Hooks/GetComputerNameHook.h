#pragma once

#include "core/HookManager/Hook/InlineHook/InlineHook.h"
#include <QLoggingCategory>
#include <string>

Q_DECLARE_LOGGING_CATEGORY(getComputerNameHookLog)

/**
 * @brief Специализированный хук для перехвата функции GetComputerNameA.
 * @details Этот хук подменяет имя компьютера, возвращаемое системой,
 * на заданное пользователем значение. Оригинальная функция GetComputerNameA не вызывается.
 */
class GetComputerNameHook : public InlineHook
{
   public:
    /**
     * @brief Конструктор хука.
     * @param memoryManager Указатель на MemoryManager для работы с памятью целевого процесса.
     * @param fakeComputerName ANSI-строка с именем, на которое будет производиться подмена.
     */
    GetComputerNameHook(MemoryManager* memoryManager, const std::string& fakeComputerName);

    /**
     * @brief Деструктор. Освобождает память, выделенную в целевом процессе.
     */
    ~GetComputerNameHook() override;

    /**
     * @brief Снимает хук и освобождает всю выделенную в процессе память.
     * @return true, если успешно.
     */
    bool uninstall() override;

   protected:
    /**
     * @brief Генерирует и записывает в целевой процесс код трамплина.
     * @details Трамплин является самодостаточным: он не вызывает C++ код,
     * а самостоятельно выполняет всю логику по копированию заранее
     * записанного имени в буферы целевой функции.
     * @return true, если трамплин успешно сгенерирован и записан.
     */
    bool generateTrampoline() override;

   private:
    /// @brief Имя компьютера, которое мы будем подставлять.
    std::string m_fakeComputerName;

    /// @brief Указатель на наше поддельное имя, но в памяти ЦЕЛЕВОГО процесса.
    void* m_remoteStringPtr = nullptr;

    /// @brief Статический адрес функции GetComputerNameA, чтобы не искать его каждый раз.
    static uintptr_t m_GetComputerNameA_addr;
};