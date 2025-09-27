#include "MovementManager.h"
#include <windows.h>
#include <cstdio>
#include "shared/Structures/Player.h"  // Нужен для Unit* и CMovement

// --- БЛОК 1: ВСЯ ЛОГИКА ДВИЖЕНИЯ ИЗ MAINLOOPHOOK ПЕРЕЕЗЖАЕТ СЮДА ---
namespace GameFunctions
{
// Глобальная переменная игры, хранящая "тик" для команд ввода
volatile uint32_t* g_timeTickForInput = (uint32_t*)0x00B499A4;

// Сигнатура для "пинка" сервера, чтобы он узнал о новом повороте
typedef int(__thiscall* CMovement_BuildAndQueue_ToggleRunCommand_t)(void* pThis, uint32_t timeTick, int runStateFlag);
const CMovement_BuildAndQueue_ToggleRunCommand_t BuildAndQueue_ToggleRunCommand_Native =
    (CMovement_BuildAndQueue_ToggleRunCommand_t)0x006ECF10;

// Сигнатура для непосредственной установки угла поворота на клиенте
typedef void(__thiscall* SetOrientation_t)(void* this_ptr, float new_orientation);
const SetOrientation_t SetOrientation_Native = (SetOrientation_t)0x00989B70;
}  // namespace GameFunctions

namespace CtmOffsets
{
constexpr uintptr_t CTM_X_COORD = 0xCA1264;
constexpr uintptr_t CTM_Y_COORD = 0xCA1268;
constexpr uintptr_t CTM_Z_COORD = 0xCA126C;
constexpr uintptr_t CTM_ACTION_TYPE = 0xCA11F4;
}  // namespace CtmOffsets

enum class CtmActionType : int
{
    MOVE_TO = 4,
};

void MovementManager::ExecuteCommand(const ClientCommand& cmd, uintptr_t playerPtr)
{
    switch (cmd.type)
    {
        case ClientCommandType::MoveTo:
        {
            // --- ЛОГИКА ИЗ СТАРОГО `case` ---
            *(float*)CtmOffsets::CTM_X_COORD = cmd.position.x;
            *(float*)CtmOffsets::CTM_Y_COORD = cmd.position.y;
            *(float*)CtmOffsets::CTM_Z_COORD = cmd.position.z;
            *(int*)CtmOffsets::CTM_ACTION_TYPE = static_cast<int>(CtmActionType::MOVE_TO);

            char debugMsg[256];
            sprintf_s(debugMsg, "MDBot_Client [MM]: Executed MoveTo command to (%.2f, %.2f, %.2f).", cmd.position.x,
                      cmd.position.y, cmd.position.z);
            OutputDebugStringA(debugMsg);
            break;
        }

        case ClientCommandType::SetOrientation:
        {
            // --- ЛОГИКА ИЗ СТАРОГО `case` ---
            if (playerPtr != 0)
            {
                Unit* playerUnit = reinterpret_cast<Unit*>(playerPtr);

                // Шаг 1: Локальный поворот
                GameFunctions::SetOrientation_Native(&playerUnit->m_movement, cmd.orientation);

                // Шаг 2: Отправка на сервер
                void* pMovement = &playerUnit->m_movement;
                uint32_t currentTick = *GameFunctions::g_timeTickForInput;
                GameFunctions::BuildAndQueue_ToggleRunCommand_Native(pMovement, currentTick, 0);

                char debugMsg[256];
                sprintf_s(debugMsg,
                          "MDBot_Client [MM]: SetOrientation (Angle: %.2f), triggered server update with tick %u.",
                          cmd.orientation, currentTick);
                OutputDebugStringA(debugMsg);
            }
            break;
        }
    }
}