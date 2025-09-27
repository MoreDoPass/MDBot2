#include "MainLoopHook.h"
#include <windows.h>
#include <cstdio>
#include "core/Memory/SharedMemoryConnector.h"
#include "shared/Data/SharedData.h"
#include "client/Hooks/VisibleObjectsHook.h"
#include <set>
#include "client/Managers/GameObjectManager.h"
#include "client/Managers/CharacterManager/CharacterManager.h"
#include "Managers/InteractionManager/InteractionManager.h"
#include "Managers/CombatManager/CombatManager.h"
#include "Managers/MovementManager/MovementManager.h"

#include "shared/Structures/Player.h"  // Включает Unit и WorldObject
#include "shared/Structures/GameObject.h"
#include "shared/Structures/Cooldowns.h"

extern SharedMemoryConnector* g_sharedMemory;
extern GameObjectManager* g_gameObjectManager;
extern CharacterManager* g_characterManager;
extern InteractionManager* g_interactionManager;
extern CombatManager* g_combatManager;
extern MovementManager* g_movementManager;
extern volatile uintptr_t g_playerPtr;  // <-- ПОЛУЧАЕМ ДОСТУП К УКАЗАТЕЛЮ ИЗ CharacterHook

// Передаем в конструктор базового класса наш целевой адрес
MainLoopHook::MainLoopHook() : InlineHook(0x728A27) {}

/**
 * @brief Обработчик главного игрового цикла.
 * @details Вызывается очень часто. Отвечает за две задачи:
 *          1. Выполнение команд, полученных от MDBot2.exe (например, MoveTo).
 *          2. Сбор данных о видимых объектах и отправка их в MDBot2.exe.
 * @param regs Указатель на сохраненные регистры процессора (не используется в этой функции).
 */
void MainLoopHook::handler(const Registers* regs)
{
    if (!g_sharedMemory || !g_gameObjectManager || !g_characterManager)
    {
        return;
    }

    SharedData* sharedData = g_sharedMemory->getMemoryPtr();
    if (!sharedData)
    {
        return;
    }

    // --- 1. ОБРАБОТКА КОМАНД ОТ КЛИЕНТА ---
    // Теперь мы проверяем статус PENDING
    if (sharedData->commandToDll.status == CommandStatus::Pending)
    {
        ClientCommand& cmd = sharedData->commandToDll;

        switch (cmd.type)
        {
            // --- Команды движения ---
            case ClientCommandType::MoveTo:
            case ClientCommandType::SetOrientation:
            {
                if (g_movementManager) g_movementManager->ExecuteCommand(cmd, g_playerPtr);
                break;
            }

            // --- Команды взаимодействия ---
            case ClientCommandType::NativeInteract:
            {
                if (g_interactionManager) g_interactionManager->ExecuteCommand(cmd);
                break;
            }

            // --- Команды боя ---
            case ClientCommandType::StartAutoAttack:
            case ClientCommandType::CastSpellOnTarget:
            {
                if (g_combatManager) g_combatManager->ExecuteCommand(cmd, g_playerPtr);
                break;
            }

            default:
                char debugMsg[256];
                sprintf_s(debugMsg, "MDBot_Client: Received unknown command type: %d", static_cast<int>(cmd.type));
                OutputDebugStringA(debugMsg);
                break;
        }
        sharedData->commandToDll.status = CommandStatus::Acknowledged;
    }

    // --- 2. СБОР И ОБНОВЛЕНИЕ playerdata ДАННЫХ ---
    // CharacterManager ПОЛНОСТЬЮ отвечает за PlayerData.
    g_characterManager->update(sharedData, g_playerPtr);

    // --- 3. СБОР ДАННЫХ ОБ ОБЪЕКТАХ ---
    // Второй аргумент - это указатель на нашего игрока из глобальной переменной,
    // которую обновляет CharacterHook, чтобы не обновлять его данные
    g_gameObjectManager->collect(sharedData, g_playerPtr);
}