#pragma once
#include "core/hooks/InlineHook/inlinehook.h"
#include <cstdint>

// RegisterInlineHook — хук, который сохраняет значение указанного регистра (например, EDI) в память процесса
class RegisterInlineHook : public InlineHook
{
   public:
    // regName — имя регистра (например, "edi"), bufferAddr — адрес буфера в памяти процесса, куда сохранять значение
    RegisterInlineHook(void* addr, const char* regName, uintptr_t bufferAddr, MemoryManager& mem, int minPatchSize = 5);
    ~RegisterInlineHook() override = default;

   protected:
    // Переопределяем создание трамплина: генерируем shellcode для сохранения регистра
    bool createTrampoline() override;

    const char* regName;
    uintptr_t bufferAddr;
};
