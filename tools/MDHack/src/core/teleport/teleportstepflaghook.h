#pragma once
#include "core/hooks/InlineHook/inlinehook.h"
#include <cstdint>

// Хук для выставления флага, если ecx == playerStructAddr
class TeleportStepFlagHook : public InlineHook
{
   public:
    TeleportStepFlagHook(void* addr, uintptr_t playerStructAddr, uintptr_t flagBufferAddr, MemoryManager& mem,
                         int patchSize = 5);
    ~TeleportStepFlagHook() override;

   protected:
    bool createTrampoline() override;

   private:
    uintptr_t playerStructAddr;
    uintptr_t flagBufferAddr;
};
