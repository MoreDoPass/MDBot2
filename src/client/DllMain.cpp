#include <windows.h>
#include "Hooks/GameLoopHook.h"
#include "Core/Memory/SharedMemoryConnector.h"
#include "Hooks/VisibleObjectsHook.h"
#include "shared/Data/SharedData.h"

// Глобальный УКАЗАТЕЛЬ на наш хук
GameLoopHook* g_gameLoopHook = nullptr;
VisibleObjectsHook* g_visibleObjectsHook = nullptr;
SharedMemoryConnector* g_sharedMemory = nullptr;

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

    // Создаем и устанавливаем оба хука
    OutputDebugStringA("MDBot_Client: Installing VisibleObjectsHook (Collector)...");
    g_visibleObjectsHook = new VisibleObjectsHook();
    if (!g_visibleObjectsHook->install())
    {
        OutputDebugStringA("MDBot_Client: ERROR - Failed to install VisibleObjectsHook.");
        delete g_visibleObjectsHook;
        g_visibleObjectsHook = nullptr;
        delete g_sharedMemory;
        g_sharedMemory = nullptr;
        return 1;
    }
    OutputDebugStringA("MDBot_Client: VisibleObjectsHook installed successfully.");

    OutputDebugStringA("MDBot_Client: Installing GameLoopHook (Handler)...");
    g_gameLoopHook = new GameLoopHook();
    if (!g_gameLoopHook->install())
    {
        OutputDebugStringA("MDBot_Client: ERROR - Failed to install GameLoopHook.");
        g_visibleObjectsHook->uninstall();  // <-- Не забываем удалить предыдущий хук в случае ошибки
        delete g_visibleObjectsHook;
        g_visibleObjectsHook = nullptr;
        delete g_gameLoopHook;
        g_gameLoopHook = nullptr;
        delete g_sharedMemory;
        g_sharedMemory = nullptr;
        return 1;
    }
    OutputDebugStringA("MDBot_Client: GameLoopHook installed successfully.");

    OutputDebugStringA("MDBot_Client: Initialization complete.");
    return 0;
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
                if (g_gameLoopHook)
                {
                    g_gameLoopHook->uninstall();
                    delete g_gameLoopHook;
                    g_gameLoopHook = nullptr;
                }
                if (g_visibleObjectsHook)
                {
                    g_visibleObjectsHook->uninstall();
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