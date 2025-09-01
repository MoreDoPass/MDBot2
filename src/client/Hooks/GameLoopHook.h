#pragma once
#include "Core/Hooking/InlineHook.h"

class GameLoopHook : public InlineHook
{
   public:
    GameLoopHook();

   protected:
    void handler(const Registers* regs) override;
};