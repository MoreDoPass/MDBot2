#include "CtMEnablerHook.h"
#include <windows.h>

/// @brief Адрес функции, которую мы хукаем для получения указателя.
constexpr uintptr_t WORLD_ENTER_HOOK_ADDR = 0x0051DA2F;
/// @brief Смещение от базового указателя до флага CtM.
constexpr int CTM_FLAG_OFFSET = 0x30;

/**
 * @brief Конструктор. Передает базовому классу адрес для установки хука.
 */
CtMEnablerHook::CtMEnablerHook() : InlineHook(WORLD_ENTER_HOOK_ADDR)
{
    OutputDebugStringA("MDBot_Client: CtMEnablerHook (v2) object created.");
}

/**
 * @brief Обработчик хука. Вызывается при выполнении кода по адресу CTM_ENABLE_HOOK_ADDR.
 * @param regs Структура с сохраненными регистрами. Нам нужен ECX.
 */
/**
 * @brief Обработчик хука. Вызывается при выполнении кода по адресу WORLD_ENTER_HOOK_ADDR.
 * @param regs Структура с сохраненными регистрами. Нам нужен EAX.
 */
void CtMEnablerHook::handler(const Registers* regs)
{
    OutputDebugStringA("MDBot_Client: >>> CtMEnablerHook (v2) handler TRIGGERED! <<<");

    if (!regs)
    {
        OutputDebugStringA("MDBot_Client: Registers are null, handler exits.");
        return;
    }

    try
    {
        // Трамплин уже выполнил оригинальную инструкцию "mov [0xBD08F4], eax".
        // Это значит, что нужный нам базовый указатель теперь лежит и в регистре EAX,
        // и в памяти по статическому адресу. Мы можем взять его из регистра - это быстрее.
        uintptr_t basePtr = regs->eax;

        // Если указатель нулевой, ничего не делаем.
        if (basePtr == 0)
        {
            OutputDebugStringA("MDBot_Client: Base pointer from EAX is null, skipping.");
            return;
        }

        // Вычисляем адрес флага CtM.
        uintptr_t ctmFlagAddress = basePtr + CTM_FLAG_OFFSET;

        // Записываем 1 (DWORD), чтобы включить CtM.
        *(reinterpret_cast<DWORD*>(ctmFlagAddress)) = 1;

        char debugMsg[256];
        sprintf_s(debugMsg, "MDBot_Client: CtM enabled via base pointer 0x%X. Flag address: 0x%X", basePtr,
                  ctmFlagAddress);
        OutputDebugStringA(debugMsg);
    }
    catch (...)
    {
        OutputDebugStringA("MDBot_Client: CRITICAL - Exception caught in CtMEnablerHook (v2) handler!");
    }

    // ВАЖНО: Мы НЕ вызываем uninstall(). Хук должен остаться активным
    // для повторного срабатывания при смене локаций.
}