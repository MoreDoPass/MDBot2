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

/**
 * @brief Извлекает Entry ID из полного 64-битного GUID.
 * @details Работает только для типов Unit и GameObject. Для остальных вернет 0.
 * @param guid Полный 64-битный GUID.
 * @param type Тип объекта, чтобы не пытаться извлечь ID у игрока.
 * @return 32-битный Entry ID или 0, если ID не применим.
 */
static int32_t getEntryIdFromGuid(uint64_t guid, GameObjectType type)
{
    if (type == GameObjectType::Unit || type == GameObjectType::GameObject)
    {
        // 1. Сдвигаем GUID на 24 бита вправо, чтобы отсечь уникальный счетчик.
        // 2. Применяем маску 0x00FFFFFF, чтобы отсечь старшие байты (тип, подтип и т.д.).
        return static_cast<int32_t>((guid >> 24) & 0x00FFFFFF);
    }
    return 0;
}

/**
 * @brief Обработчик главного игрового цикла.
 * @details Вызывается очень часто. Отвечает за две задачи:
 *          1. Выполнение команд, полученных от MDBot2.exe (например, MoveTo).
 *          2. Сбор данных о видимых объектах и отправка их в MDBot2.exe.
 * @param regs Указатель на сохраненные регистры процессора (не используется в этой функции).
 */
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

    // --- 1. ОБРАБОТКА КОМАНД ОТ КЛИЕНТА ---
    if (sharedData->commandToDll.type != ClientCommandType::None)
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
            default:
                break;
        }
        // Сбрасываем команду после выполнения
        cmd.type = ClientCommandType::None;
    }

    // --- 2. СБОР ДАННЫХ ОБ ОБЪЕКТАХ ---
    std::set<uintptr_t> objectPointers = g_visibleObjectsHook->getAndClearObjects();

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

            // --- ЗАПОЛНЕНИЕ ДАННЫХ ---
            info.guid = worldObject->guid;
            info.type = worldObject->objectType;
            info.baseAddress = objectPtr;

            // --- ГЛАВНОЕ ИЗМЕНЕНИЕ: ВЫЧИСЛЯЕМ И ЗАПИСЫВАЕМ ENTRY ID ---
            info.entryId = getEntryIdFromGuid(info.guid, info.type);

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
}