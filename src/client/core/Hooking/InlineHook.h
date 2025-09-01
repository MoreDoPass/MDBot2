#pragma once
#include <cstdint>
#include <vector>
#include <capstone/capstone.h>
#include "Core/Hooking/Registers.h"  // <-- Подключаем новый заголовок

/**
 * @class InlineHook
 * @brief Базовый класс для создания inline-хуков ("трамплинов").
 * @details Инкапсулирует логику дизассемблирования (Capstone), выделения памяти,
 * генерации ассемблерного шеллкода и установки/снятия JMP-патча.
 * Является универсальным инструментом для создания конкретных хуков.
 */
class InlineHook
{
   public:
    /**
     * @brief Конструктор.
     * @param address Адрес в памяти, на который будет установлен хук.
     */
    explicit InlineHook(uintptr_t address);

    /**
     * @brief Деструктор. Гарантирует, что хук будет снят при удалении объекта.
     */
    virtual ~InlineHook();

    /**
     * @brief Устанавливает хук.
     * @return true в случае успеха, false в случае ошибки.
     */
    bool install();

    /**
     * @brief Снимает хук и восстанавливает оригинальные байты.
     */
    void uninstall();

   protected:
    /**
     * @brief Виртуальный обработчик хука.
     * @details Переопределяется в дочерних классах для выполнения полезной нагрузки.
     * @param regs Указатель на структуру с сохраненными регистрами на момент вызова хука.
     */
    virtual void handler(const Registers* regs) = 0;

    /// @brief Указатель на трамплин - область памяти с оригинальными инструкциями и JMP'ом назад.
    void* m_trampoline = nullptr;

   private:
    /**
     * @brief Вычисляет минимальный размер инструкций для безопасной замены на JMP (>= 5 байт).
     * @return Размер в байтах или 0 в случае ошибки.
     */
    size_t calculatePatchSize();

    /**
     * @brief Статический "мост" из мира ASM в мир C++.
     * @details Вызывается из ассемблерной обертки, принимает указатель на объект хука
     * и указатель на сохраненные на стеке регистры, после чего вызывает виртуальный метод handler.
     * @param self Указатель на экземпляр класса InlineHook.
     * @param regs Указатель на структуру Registers на стеке.
     */
    static void __stdcall CppBridge(InlineHook* self, const Registers* regs);

    /// @brief Адрес для установки хука.
    uintptr_t m_address;
    /// @brief Флаг, установлен ли хук в данный момент.
    bool m_installed = false;
    /// @brief Копия оригинальных байт, которые были заменены JMP-патчем.
    std::vector<uint8_t> m_originalBytes;
    /// @brief Рассчитанный размер патча.
    size_t m_patchSize = 0;
    /// @brief Указатель на выделенную память для нашего ассемблерного обработчика.
    void* m_handlerStub = nullptr;
};