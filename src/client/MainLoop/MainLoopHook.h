#pragma once
#include "Core/Hooking/InlineHook.h"

class MainLoopHook : public InlineHook
{
   public:
    MainLoopHook();

   protected:
    void handler(const Registers* regs) override;
};