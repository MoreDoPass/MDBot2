#include "CharacterHook.h"
#include <windows.h>  // Для OutputDebugStringA

/// @brief Адрес функции, где в EAX загружается указатель на игрока.
constexpr uintptr_t PLAYER_PTR_HOOK_ADDR = 0x4FA64E;

/// @brief Глобальная переменная для хранения указателя на структуру игрока.
///        volatile, чтобы компилятор не оптимизировал доступ к ней.
volatile uintptr_t g_playerPtr = 0;

/**
 * @brief Конструктор. Передает базовому классу адрес для установки хука.
 */
CharacterHook::CharacterHook() : InlineHook(PLAYER_PTR_HOOK_ADDR)
{
    OutputDebugStringA("MDBot_Client: CharacterHook object created.");
}

/**
 * @brief Обработчик хука. Вызывается при выполнении кода по адресу PLAYER_PTR_HOOK_ADDR.
 * @param regs Структура с сохраненными регистрами. Нам нужен EAX.
 */
void CharacterHook::handler(const Registers* regs)
{
    if (!regs)
    {
        return;
    }

    // Просто сохраняем значение из EAX в нашу глобальную переменную.
    // Это очень быстрая операция, которая не замедлит игру.
    g_playerPtr = regs->eax;

    // Никакого логирования здесь! Эта функция может вызываться очень часто.
    // Логирование может вызвать лаги.
}