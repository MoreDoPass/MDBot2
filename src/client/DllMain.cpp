#include <windows.h>
#include "Hooks/GameLoopHook.h"
#include "Core/Memory/SharedMemoryConnector.h"
#include "Hooks/VisibleObjectsHook.h"
#include "Hooks/CtMEnablerHook.h"
#include "Hooks/CharacterHook.h"
#include "shared/Data/SharedData.h"

// Глобальный УКАЗАТЕЛЬ на наш хук
GameLoopHook* g_gameLoopHook = nullptr;
VisibleObjectsHook* g_visibleObjectsHook = nullptr;
CtMEnablerHook* g_ctmEnablerHook = nullptr;
CharacterHook* g_characterHook = nullptr;
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

    OutputDebugStringA("MDBot_Client: Installing GameLoopHook (Handler)...");
    g_gameLoopHook = new GameLoopHook();
    if (!g_gameLoopHook->install())
    {
        OutputDebugStringA("MDBot_Client: ERROR - Failed to install GameLoopHook.");
        goto cleanup_and_fail;
    }
    OutputDebugStringA("MDBot_Client: GameLoopHook installed successfully.");

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

    OutputDebugStringA("MDBot_Client: Initialization complete. All systems running.");
    return 0;

cleanup_and_fail:
    // Блок очистки в случае критической ошибки установки хука
    if (g_characterHook)
    {
        delete g_characterHook;
        g_characterHook = nullptr;
    }
    if (g_gameLoopHook)
    {
        delete g_gameLoopHook;
        g_gameLoopHook = nullptr;
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
                if (g_gameLoopHook)
                {
                    delete g_gameLoopHook;
                    g_gameLoopHook = nullptr;
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