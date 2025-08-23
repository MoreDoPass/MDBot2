#include "hookmanager.h"

HookManager::HookManager() : hookCount(0)
{
    for (int i = 0; i < MAX_HOOKS; ++i) hooks[i] = nullptr;
}

HookManager::~HookManager()
{
    removeAll();
}

bool HookManager::addHook(IHook* hook)
{
    if (hookCount >= MAX_HOOKS) return false;
    hooks[hookCount++] = hook;
    return true;
}

bool HookManager::removeHook(IHook* hook)
{
    for (int i = 0; i < hookCount; ++i)
    {
        if (hooks[i] == hook)
        {
            for (int j = i; j < hookCount - 1; ++j)
            {
                hooks[j] = hooks[j + 1];
            }
            hooks[--hookCount] = nullptr;
            return true;
        }
    }
    return false;
}

void HookManager::installAll()
{
    for (int i = 0; i < hookCount; ++i)
    {
        if (hooks[i] && !hooks[i]->isInstalled())
        {
            hooks[i]->install();
        }
    }
}

void HookManager::removeAll()
{
    for (int i = 0; i < hookCount; ++i)
    {
        if (hooks[i] && hooks[i]->isInstalled())
        {
            hooks[i]->remove();
        }
    }
}
