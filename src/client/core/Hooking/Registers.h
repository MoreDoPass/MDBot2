#pragma once
#include <cstdint>

/**
 * @struct Registers
 * @brief Структура для хранения состояния регистров общего назначения.
 * @details Порядок полей соответствует порядку, в котором инструкция PUSHAD
 * помещает регистры в стек (EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI).
 * Мы обращаемся к ним через указатель на стек, поэтому порядок важен.
 * PUSHAD сохраняет в порядке: EAX, ECX, EDX, EBX, ESP (ориг.), EBP, ESI, EDI.
 * POPAD восстанавливает в обратном порядке.
 */
struct Registers
{
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp_dummy;  // Пропускаем, так как ESP меняется и это значение нам не нужно
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;
};