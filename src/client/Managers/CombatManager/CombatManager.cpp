#include "CombatManager.h"
#include <windows.h>
#include <cstdio>
#include "shared/Structures/Player.h"  // Нужен для reinterpret_cast<Unit*>

// --- БЛОК 1: ПЕРЕНОСИМ ВСЕ БОЕВЫЕ ЗАВИСИМОСТИ ИЗ MAINLOOPHOOK ---
namespace GameFunctions
{
// Для CastSpellOnTarget
typedef int(__cdecl* LUA_SpellHandler_t)(int spellId, void* pAoETargetObject, int targetGuid_Low, int targetGuid_High,
                                         char suppressErrors);
const LUA_SpellHandler_t CastSpell_Lua_Or_Handler = (LUA_SpellHandler_t)0x0080DA40;

// Для StartAutoAttack
typedef int(__thiscall* Unit_SetAttacker_t)(void* pThis, uint32_t guid_low, uint32_t guid_high, int a3);
const Unit_SetAttacker_t Unit_SetAttacker_Native = (Unit_SetAttacker_t)0x0072C2B0;
}  // namespace GameFunctions

void CombatManager::ExecuteCommand(const ClientCommand& cmd, uintptr_t playerPtr)
{
    // Теперь у нас несколько команд, поэтому используем switch
    switch (cmd.type)
    {
        case ClientCommandType::StartAutoAttack:
        {
            // --- ЛОГИКА ИЗ СТАРОГО `case` ПОЛНОСТЬЮ ПЕРЕЕХАЛА СЮДА ---
            if (playerPtr != 0 && cmd.targetGuid != 0)
            {
                uint32_t guid_low = (uint32_t)(cmd.targetGuid & 0xFFFFFFFF);
                uint32_t guid_high = (uint32_t)(cmd.targetGuid >> 32);
                void* pThis = (void*)playerPtr;
                int a3 = 0;

                GameFunctions::Unit_SetAttacker_Native(pThis, guid_low, guid_high, a3);

                char debugMsg[256];
                sprintf_s(debugMsg, "MDBot_Client [CM]: Executed NATIVE Attack for GUID: %llX", cmd.targetGuid);
                OutputDebugStringA(debugMsg);
            }
            else
            {
                char debugMsg[256];
                sprintf_s(debugMsg, "MDBot_Client [CM]: SKIPPED Attack. PlayerPtr: %p, TargetGUID: %llX",
                          (void*)playerPtr, cmd.targetGuid);
                OutputDebugStringA(debugMsg);
            }
            break;
        }

        case ClientCommandType::CastSpellOnTarget:
        {
            // --- И ЭТА ЛОГИКА ТОЖЕ ПЕРЕЕХАЛА СЮДА ---
            int spellId = cmd.spellId;
            uint64_t targetGUID = cmd.targetGuid;
            int guid_low = (int)(targetGUID & 0xFFFFFFFF);
            int guid_high = (int)(targetGUID >> 32);

            GameFunctions::CastSpell_Lua_Or_Handler(spellId, NULL, guid_low, guid_high, 0);

            char debugMsg[256];
            sprintf_s(debugMsg, "MDBot_Client [CM]: Executed CastSpellOnTarget. SpellID: %d, Target: %llX", spellId,
                      targetGUID);
            OutputDebugStringA(debugMsg);
            break;
        }
    }
}