#include "MainLoopHook.h"
#include <windows.h>
#include <cstdio>
#include "core/Memory/SharedMemoryConnector.h"  // <-- Подключаем коннектор
#include "shared/Data/SharedData.h"             // <-- Подключаем структуры
#include "client/Hooks/VisibleObjectsHook.h"
#include <set>  // <-- ИСПРАВЛЕНИЕ: Подключаем заголовок для std::set
#include "client/Managers/GameObjectManager.h"
#include "client/Managers/CharacterManager/CharacterManager.h"

#include "shared/Structures/Player.h"  // Включает Unit и WorldObject
#include "shared/Structures/GameObject.h"
#include "shared/Structures/Cooldowns.h"

// this_ptr - это указатель на CMovement, который передается через регистр ECX
// new_orientation - это float, который передается через стек
typedef void(__thiscall* SetOrientation_t)(void* this_ptr, float new_orientation);
const SetOrientation_t SetOrientation_Native = (SetOrientation_t)0x00989B70;  // Адрес из вашего анализа

typedef void(__cdecl* InteractByGUID_t)(uint32_t guid_low, uint32_t guid_high);
const InteractByGUID_t WowInteractByGUID = (InteractByGUID_t)0x005277B0;

typedef int(__cdecl* LUA_SpellHandler_t)(int spellId, void* pAoETargetObject, int targetGuid_Low, int targetGuid_High,
                                         char suppressErrors);
const LUA_SpellHandler_t CastSpell_Lua_Or_Handler = (LUA_SpellHandler_t)0x0080DA40;

// Сигнатура: int __thiscall Unit::SetAttacker(void* pThis, uint32_t guid_low, uint32_t guid_high, int a3);
// Примечание: Мы передаем GUID двумя 32-битными частями, так как __thiscall
// не поддерживает 64-битные аргументы напрямую в старых компиляторах.
typedef int(__thiscall* Unit_SetAttacker_t)(void* pThis, uint32_t guid_low, uint32_t guid_high, int a3);
const Unit_SetAttacker_t Unit_SetAttacker_Native = (Unit_SetAttacker_t)0x0072C2B0;

namespace CtmOffsets
{
constexpr uintptr_t CTM_X_COORD = 0xCA1264;
constexpr uintptr_t CTM_Y_COORD = 0xCA1268;
constexpr uintptr_t CTM_Z_COORD = 0xCA126C;

constexpr uintptr_t CTM_GUID_LOW = 0x00CA11F8;
constexpr uintptr_t CTM_GUID_HIGH = 0x00CA11FC;

constexpr uintptr_t CTM_ACTION_TYPE = 0xCA11F4;
constexpr uintptr_t CTM_INTERACTION_DISTANCE = 0xCA11E4;

// Добавим и другие, если понадобятся (GUID, distance и т.д.)
}  // namespace CtmOffsets

// --- НОВЫЙ БЛОК: Перечисление типов действий CtM из старого CtmExecutor ---
enum class CtmActionType : int
{
    FACE_TARGET = 1,
    MOVE_TO = 4,
    INTERACT_NPC = 5,
    LOOT = 6,
    ATTACK_GUID = 11,
};

extern SharedMemoryConnector* g_sharedMemory;
extern GameObjectManager* g_gameObjectManager;
extern CharacterManager* g_characterManager;
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
        char debugMsg[256];

        switch (cmd.type)
        {
            case ClientCommandType::MoveTo:
            {
                *(float*)CtmOffsets::CTM_X_COORD = cmd.position.x;
                *(float*)CtmOffsets::CTM_Y_COORD = cmd.position.y;
                *(float*)CtmOffsets::CTM_Z_COORD = cmd.position.z;
                *(int*)CtmOffsets::CTM_ACTION_TYPE = static_cast<int>(CtmActionType::MOVE_TO);

                sprintf_s(debugMsg, "MDBot_Client: Executed MoveTo command to (%.2f, %.2f, %.2f) via memory write.",
                          cmd.position.x, cmd.position.y, cmd.position.z);
                OutputDebugStringA(debugMsg);
                break;
            }

            case ClientCommandType::SetOrientation:
            {
                // Проверяем, что у нас есть валидный указатель на нашего игрока
                if (g_playerPtr != 0)
                {
                    // Преобразуем общий указатель в указатель на структуру Unit
                    Unit* playerUnit = reinterpret_cast<Unit*>(g_playerPtr);

                    // Вызываем нативную функцию игры.
                    // В качестве первого аргумента (который пойдет в ECX) передаем
                    // указатель на вложенную структуру m_movement.
                    // В качестве второго - угол из нашей команды.
                    SetOrientation_Native(&playerUnit->m_movement, cmd.orientation);

                    // Для отладки, чтобы убедиться, что команда выполнилась
                    char debugMsg[256];
                    sprintf_s(debugMsg, "MDBot_Client: Executed SetOrientation. Angle: %.2f\n", cmd.orientation);
                    OutputDebugStringA(debugMsg);
                }
                break;
            }

            case ClientCommandType::NativeInteract:
            {
                // --- ПРАВИЛЬНАЯ ЛОГИКА ---
                // 1. Разбиваем 64-битный GUID из команды на две 32-битные части
                uint32_t guid_low = (uint32_t)(cmd.targetGuid & 0xFFFFFFFF);
                uint32_t guid_high = (uint32_t)(cmd.targetGuid >> 32);

                // 2. Вызываем функцию, передавая ей две части как отдельные аргументы
                WowInteractByGUID(guid_low, guid_high);

                sprintf_s(debugMsg, "MDBot_Client: Executed NATIVE Interact for GUID: %llX (Low: %X, High: %X)",
                          cmd.targetGuid, guid_low, guid_high);
                OutputDebugStringA(debugMsg);
                break;
            }

            case ClientCommandType::StartAutoAttack:
            {
                // 1. Проверяем, что у нас есть указатели на игрока и цель
                if (g_playerPtr != 0 && cmd.targetGuid != 0)
                {
                    // 2. Разбиваем 64-битный GUID цели на две 32-битные части
                    uint32_t guid_low = (uint32_t)(cmd.targetGuid & 0xFFFFFFFF);
                    uint32_t guid_high = (uint32_t)(cmd.targetGuid >> 32);

                    // 3. Указатель на объект игрока (будет передан в ECX)
                    void* pThis = (void*)g_playerPtr;

                    // 4. Третий аргумент, как вы выяснили, равен 0
                    int a3 = 0;

                    // 5. Вызываем нативную функцию!
                    Unit_SetAttacker_Native(pThis, guid_low, guid_high, a3);

                    sprintf_s(debugMsg, "MDBot_Client: Executed NATIVE Attack for GUID: %llX", cmd.targetGuid);
                    OutputDebugStringA(debugMsg);
                }
                else
                {
                    // Логируем, если чего-то не хватает, чтобы помочь с отладкой
                    sprintf_s(debugMsg, "MDBot_Client: SKIPPED Attack command. PlayerPtr: %p, TargetGUID: %llX",
                              (void*)g_playerPtr, cmd.targetGuid);
                    OutputDebugStringA(debugMsg);
                }
                break;
            }

            // --- НАШ НОВЫЙ ОБРАБОТЧИК ---
            case ClientCommandType::CastSpellOnTarget:
            {
                // 1. Читаем параметры из команды
                int spellId = cmd.spellId;
                uint64_t targetGUID = cmd.targetGuid;

                // 2. Разбиваем GUID на две 32-битные части
                int guid_low = (int)(targetGUID & 0xFFFFFFFF);
                int guid_high = (int)(targetGUID >> 32);

                // 3. Вызываем функцию игры!
                CastSpell_Lua_Or_Handler(spellId, NULL, guid_low, guid_high, 0);

                sprintf_s(debugMsg, "MDBot_Client: Executed CastSpellOnTarget. SpellID: %d, Target: %llX", spellId,
                          targetGUID);
                OutputDebugStringA(debugMsg);
                break;
            }
                // -----------------------------

            default:
                // Можно добавить лог для неизвестных команд
                sprintf_s(debugMsg, "MDBot_Client: Received unknown command type: %d", static_cast<int>(cmd.type));
                OutputDebugStringA(debugMsg);
                break;
        }

        // Сообщаем "мозгу", что команда выполнена.
        sharedData->commandToDll.status = CommandStatus::Acknowledged;
    }

    // --- 2. СБОР И ОБНОВЛЕНИЕ playerdata ДАННЫХ ---
    // CharacterManager ПОЛНОСТЬЮ отвечает за PlayerData.
    g_characterManager->update(sharedData, g_playerPtr);

    // --- 3. СБОР ДАННЫХ ОБ ОБЪЕКТАХ ---
    // Второй аргумент - это указатель на нашего игрока из глобальной переменной,
    // которую обновляет CharacterHook.
    g_gameObjectManager->collect(sharedData, g_playerPtr);
}