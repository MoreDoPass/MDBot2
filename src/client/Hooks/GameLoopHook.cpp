#include "GameLoopHook.h"
#include <windows.h>
#include "core/Memory/SharedMemoryConnector.h"  // <-- Подключаем коннектор
#include "shared/Data/SharedData.h"             // <-- Подключаем структуры
#include "VisibleObjectsHook.h"
#include <set>  // <-- ИСПРАВЛЕНИЕ: Подключаем заголовок для std::set

#include "shared/Structures/Player.h"  // Включает Unit и WorldObject
#include "shared/Structures/GameObject.h"

namespace CtmOffsets
{
constexpr uintptr_t CTM_X_COORD = 0xCA1264;
constexpr uintptr_t CTM_Y_COORD = 0xCA1268;
constexpr uintptr_t CTM_Z_COORD = 0xCA126C;
constexpr uintptr_t CTM_ACTION_TYPE = 0xCA11F4;
// Добавим и другие, если понадобятся (GUID, distance и т.д.)
}  // namespace CtmOffsets

// --- НОВЫЙ БЛОК: Перечисление типов действий CtM из старого CtmExecutor ---
enum class CtmActionType : int
{
    MOVE_TO = 4,
    INTERACT_NPC = 5,
    LOOT = 6,
    ATTACK_GUID = 11,
    // и т.д.
};

extern SharedMemoryConnector* g_sharedMemory;
extern VisibleObjectsHook* g_visibleObjectsHook;  // <-- Добавляем доступ к сборщику

// Передаем в конструктор базового класса наш целевой адрес
GameLoopHook::GameLoopHook() : InlineHook(0x728A27) {}

void GameLoopHook::handler(const Registers* regs)
{
    if (!g_sharedMemory || !g_visibleObjectsHook)
    {
        return;
    }

    // Получаем прямой доступ к общей памяти
    SharedData* sharedData = g_sharedMemory->getMemoryPtr();
    if (!sharedData)
    {
        return;
    }

    // --- НОВЫЙ БЛОК: ОБРАБОТКА КОМАНД ОТ КЛИЕНТА (через запись в память) ---
    if (sharedData->commandToDll.type != ClientCommandType::None)
    {
        ClientCommand& cmd = sharedData->commandToDll;
        char debugMsg[256];

        switch (cmd.type)
        {
            case ClientCommandType::MoveTo:
            {
                // 1. Записываем координаты
                *(float*)CtmOffsets::CTM_X_COORD = cmd.position.x;
                *(float*)CtmOffsets::CTM_Y_COORD = cmd.position.y;
                *(float*)CtmOffsets::CTM_Z_COORD = cmd.position.z;

                // 2. В самом конце, как триггер, записываем тип действия
                *(int*)CtmOffsets::CTM_ACTION_TYPE = static_cast<int>(CtmActionType::MOVE_TO);

                sprintf_s(debugMsg, "MDBot_Client: Executed MoveTo command to (%.2f, %.2f, %.2f) via memory write.",
                          cmd.position.x, cmd.position.y, cmd.position.z);
                OutputDebugStringA(debugMsg);
                break;
            }
            // Сюда можно будет добавить case Attack, case Interact и т.д.
            default:
                break;
        }

        // КРИТИЧЕСКИ ВАЖНО: Сбрасываем команду после выполнения
        cmd.type = ClientCommandType::None;
    }
    // --- КОНЕЦ НОВОГО БЛОКА ---

    // --- Сбор данных об объектах (старый код) ---
    std::set<uintptr_t> objectPointers = g_visibleObjectsHook->getAndClearObjects();

    // Заполняем данные об объектах в sharedData
    sharedData->visibleObjectCount = 0;
    for (uintptr_t objectPtr : objectPointers)
    {
        if (sharedData->visibleObjectCount >= MAX_VISIBLE_OBJECTS)
        {
            break;
        }

        try
        {
            WorldObject* worldObject = reinterpret_cast<WorldObject*>(objectPtr);
            GameObjectInfo& info = sharedData->visibleObjects[sharedData->visibleObjectCount];

            info.guid = worldObject->guid;
            info.type = worldObject->objectType;
            info.baseAddress = objectPtr;

            switch (info.type)
            {
                case GameObjectType::Unit:
                case GameObjectType::Player:
                {
                    Unit* unit = reinterpret_cast<Unit*>(objectPtr);
                    info.position = unit->position;
                    info.health = unit->health;
                    info.maxHealth = unit->maxHealth;
                    info.mana = unit->mana;
                    info.maxMana = unit->maxMana;
                    info.level = unit->level;
                    break;
                }
                case GameObjectType::GameObject:
                {
                    GameObject* gameObject = reinterpret_cast<GameObject*>(objectPtr);
                    info.position = gameObject->position;
                    break;
                }
                default:
                {
                    break;
                }
            }
            sharedData->visibleObjectCount++;
        }
        catch (...)
        {
            OutputDebugStringA("MDBot_Client: CRITICAL - Exception caught while reading object memory.");
        }
    }

    // TODO: Заполнять реальные данные игрока
    sharedData->player.health = 1234;
    sharedData->player.maxHealth = 5678;
    sharedData->player.position = {1.0f, 2.0f, 3.0f};

    // Старый вызов g_sharedMemory->write() больше не нужен,
    // так как мы пишем в sharedData напрямую.
}