#ifndef HOOKMANAGER_H
#define HOOKMANAGER_H

#include "ihook.h"
#define MAX_HOOKS 32

class HookManager
{
   public:
    HookManager();
    ~HookManager();

    bool addHook(IHook* hook);     // Добавить хук
    bool removeHook(IHook* hook);  // Удалить хук
    void installAll();             // Установить все хуки
    void removeAll();              // Снять все хуки
   private:
    IHook* hooks[MAX_HOOKS];
    int hookCount;
};

#endif  // HOOKMANAGER_H
