#include <windows.h>
#include "MainLoop/MainLoopHook.h"
#include "Core/Memory/SharedMemoryConnector.h"
#include "Hooks/VisibleObjectsHook.h"
#include "Hooks/CtMEnablerHook.h"
#include "Hooks/CharacterHook.h"
#include "shared/Data/SharedData.h"
#include "Managers/GameObjectManager.h"
#include "Managers/CharacterManager/CharacterManager.h"
#include "Managers/InteractionManager/InteractionManager.h"
#include "Managers/CombatManager/CombatManager.h"
#include "Managers/MovementManager/MovementManager.h"

// Глобальный УКАЗАТЕЛЬ на наш хук
MainLoopHook* g_mainLoopHook = nullptr;
VisibleObjectsHook* g_visibleObjectsHook = nullptr;
CtMEnablerHook* g_ctmEnablerHook = nullptr;
CharacterHook* g_characterHook = nullptr;
SharedMemoryConnector* g_sharedMemory = nullptr;

GameObjectManager* g_gameObjectManager = nullptr;
CharacterManager* g_characterManager = nullptr;
InteractionManager* g_interactionManager = nullptr;
CombatManager* g_combatManager = nullptr;
MovementManager* g_movementManager = nullptr;

/**
 * @brief Поток-инициализатор. Создает коннектор к общей памяти и устанавливает хук.
 * @details Этот поток выполняется сразу после инжекта DLL. Вся "тяжелая" и "небезопасная"
 * для DllMain логика вынесена сюда, чтобы избежать блокировок загрузчика (loader lock).
 * @param hModule Хэндл нашего DLL-модуля.
 * @return 0 в случае успеха, 1 в случае ошибки.
 */
DWORD WINAPI Initialize(LPVOID hModule)
{
    OutputDebugStringA("MDBot_Client: Initialize thread started.");

    wchar_t sharedMemName[256];
    wsprintfW(sharedMemName, L"MDBot2_SharedBlock_%lu", GetCurrentProcessId());

    char debugMsg[512];
    wsprintfA(debugMsg, "MDBot_Client: Shared memory name is '%S'", sharedMemName);
    OutputDebugStringA(debugMsg);

    g_sharedMemory = new SharedMemoryConnector();
    if (!g_sharedMemory->open(sharedMemName, sizeof(SharedData)))
    {
        wsprintfA(debugMsg, "MDBot_Client: ERROR - Failed to open shared memory. GetLastError() = %lu", GetLastError());
        OutputDebugStringA(debugMsg);
        delete g_sharedMemory;
        g_sharedMemory = nullptr;
        return 1;
    }
    OutputDebugStringA("MDBot_Client: Shared memory opened successfully.");

    // --- 3. ПОСЛЕДОВАТЕЛЬНО УСТАНАВЛИВАЕМ ВСЕ ХУКИ ---
    // Если какой-то хук не установится, нужно откатить все предыдущие.
    // Используем goto для очистки, это один из редких случаев, где это оправдано.

    OutputDebugStringA("MDBot_Client: Installing VisibleObjectsHook (Collector)...");
    g_visibleObjectsHook = new VisibleObjectsHook();
    if (!g_visibleObjectsHook->install())
    {
        OutputDebugStringA("MDBot_Client: ERROR - Failed to install VisibleObjectsHook.");
        goto cleanup_and_fail;
    }
    OutputDebugStringA("MDBot_Client: VisibleObjectsHook installed successfully.");

    OutputDebugStringA("MDBot_Client: Installing CharacterHook (Player Ptr)...");
    g_characterHook = new CharacterHook();
    if (!g_characterHook->install())
    {
        OutputDebugStringA("MDBot_Client: ERROR - Failed to install CharacterHook.");
        goto cleanup_and_fail;
    }
    OutputDebugStringA("MDBot_Client: CharacterHook installed successfully.");

    OutputDebugStringA("MDBot_Client: Installing CtMEnablerHook...");
    g_ctmEnablerHook = new CtMEnablerHook();
    if (!g_ctmEnablerHook->install())
    {
        OutputDebugStringA("MDBot_Client: FATAL - Failed to install CtMEnablerHook! ClickToMove will NOT work.");
        // Не используем goto, так как это не настолько критично, чтобы выгружать всю DLL.
        // Просто удаляем этот конкретный хук и продолжаем.
        delete g_ctmEnablerHook;
        g_ctmEnablerHook = nullptr;
    }
    else
    {
        OutputDebugStringA("MDBot_Client: CtMEnablerHook installed successfully.");
    }

    g_gameObjectManager = new GameObjectManager(g_visibleObjectsHook);  // <-- 2. СОЗДАЕМ МЕНЕДЖЕР!
    OutputDebugStringA("MDBot_Client: GameObjectManager created.");

    g_characterManager = new CharacterManager();  // <-- 2. СОЗДАЕМ МЕНЕДЖЕР!
    OutputDebugStringA("MDBot_Client: CharacterManager created.");

    // --- НОВОЕ: Создаем экземпляры исполнительных менеджеров ---
    g_interactionManager = new InteractionManager();
    OutputDebugStringA("MDBot_Client: InteractionManager created.");

    g_combatManager = new CombatManager();
    OutputDebugStringA("MDBot_Client: CombatManager created.");

    g_movementManager = new MovementManager();
    OutputDebugStringA("MDBot_Client: MovementManager created.");

    OutputDebugStringA("MDBot_Client: Installing MainLoopHook (Handler)...");
    g_mainLoopHook = new MainLoopHook();  // <-- ИСПРАВЛЕНО
    if (!g_mainLoopHook->install())
    {
        OutputDebugStringA("MDBot_Client: ERROR - Failed to install MainLoopHook.");  // <-- ИСПРАВЛЕНО
        goto cleanup_and_fail;
    }
    OutputDebugStringA("MDBot_Client: MainLoopHook installed successfully.");  // <-- ИСПРАВЛЕНО

    OutputDebugStringA("MDBot_Client: Initialization complete. All systems running.");
    return 0;

cleanup_and_fail:
    if (g_gameObjectManager)  // <-- ДОБАВЛЕНО
    {
        delete g_gameObjectManager;
        g_gameObjectManager = nullptr;
    }
    // Блок очистки в случае критической ошибки установки хука
    if (g_characterHook)
    {
        delete g_characterHook;
        g_characterHook = nullptr;
    }
    if (g_mainLoopHook)
    {
        delete g_mainLoopHook;
        g_mainLoopHook = nullptr;
    }
    if (g_visibleObjectsHook)
    {
        delete g_visibleObjectsHook;
        g_visibleObjectsHook = nullptr;
    }
    if (g_sharedMemory)
    {
        delete g_sharedMemory;
        g_sharedMemory = nullptr;
    }
    return 1;
}

extern "C"
{
    BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
    {
        switch (fdwReason)
        {
            case DLL_PROCESS_ATTACH:
            {
                DisableThreadLibraryCalls(hinstDLL);
                HANDLE hThread = CreateThread(nullptr, 0, Initialize, hinstDLL, 0, nullptr);
                if (hThread)
                {
                    CloseHandle(hThread);
                }
                break;
            }
            case DLL_PROCESS_DETACH:
            {
                // Выгружаем ресурсы в обратном порядке установки/создания
                if (g_characterHook)  // <-- 4. ДОБАВЛЯЕМ ОЧИСТКУ
                {
                    delete g_characterHook;
                    g_characterHook = nullptr;
                }
                if (g_ctmEnablerHook)
                {
                    delete g_ctmEnablerHook;
                    g_ctmEnablerHook = nullptr;
                }
                if (g_gameObjectManager)  // <-- ДОБАВЛЕНО
                {
                    delete g_gameObjectManager;
                    g_gameObjectManager = nullptr;
                }
                if (g_interactionManager)
                {
                    delete g_interactionManager;
                    g_interactionManager = nullptr;
                }
                if (g_combatManager)
                {
                    delete g_combatManager;
                    g_combatManager = nullptr;
                }
                if (g_movementManager)
                {
                    delete g_movementManager;
                    g_movementManager = nullptr;
                }
                if (g_mainLoopHook)
                {
                    delete g_mainLoopHook;
                    g_mainLoopHook = nullptr;
                }
                if (g_visibleObjectsHook)
                {
                    delete g_visibleObjectsHook;
                    g_visibleObjectsHook = nullptr;
                }
                if (g_sharedMemory)
                {
                    delete g_sharedMemory;
                    g_sharedMemory = nullptr;
                }
                break;
            }
        }
        return TRUE;
    }
}