#include "InteractionManager.h"
#include <windows.h>  // Для OutputDebugStringA
#include <cstdio>     // Для sprintf_s

// --- БЛОК 1: ПЕРЕНОСИМ ЗАВИСИМОСТИ ИЗ MAINLOOPHOOK ---
// Вся логика, нужная ТОЛЬКО для взаимодействия, теперь живет здесь.
namespace GameFunctions
{
typedef void(__cdecl* InteractByGUID_t)(uint32_t guid_low, uint32_t guid_high);
const InteractByGUID_t WowInteractByGUID = (InteractByGUID_t)0x005277B0;
}  // namespace GameFunctions

void InteractionManager::ExecuteCommand(const ClientCommand& cmd)
{
    // Проверяем, что нам пришла именно наша команда.
    // В будущем, если менеджер будет обрабатывать несколько команд, здесь будет switch.
    if (cmd.type != ClientCommandType::NativeInteract)
    {
        return;
    }

    // --- БЛОК 2: ПЕРЕНОСИМ ЛОГИКУ ИЗ `case` БЛОКА MAINLOOPHOOK ---
    // Код полностью скопирован из твоего MainLoopHook.cpp

    // 1. Разбиваем 64-битный GUID из команды на две 32-битные части
    uint32_t guid_low = (uint32_t)(cmd.targetGuid & 0xFFFFFFFF);
    uint32_t guid_high = (uint32_t)(cmd.targetGuid >> 32);

    // 2. Вызываем функцию, передавая ей две части как отдельные аргументы
    GameFunctions::WowInteractByGUID(guid_low, guid_high);

    // 3. Логируем, что команда выполнена (добавим префикс для ясности)
    char debugMsg[256];
    sprintf_s(debugMsg, "MDBot_Client [IM]: Executed NATIVE Interact for GUID: %llX", cmd.targetGuid);
    OutputDebugStringA(debugMsg);
}