#include "GameLoopHook.h"
#include <windows.h>
#include <cstdio>
#include "core/Memory/SharedMemoryConnector.h"  // <-- Подключаем коннектор
#include "shared/Data/SharedData.h"             // <-- Подключаем структуры
#include "VisibleObjectsHook.h"
#include <set>  // <-- ИСПРАВЛЕНИЕ: Подключаем заголовок для std::set

#include "shared/Structures/Player.h"  // Включает Unit и WorldObject
#include "shared/Structures/GameObject.h"
#include "shared/Structures/Cooldowns.h"

typedef void(__cdecl* InteractByGUID_t)(uint32_t guid_low, uint32_t guid_high);
const InteractByGUID_t WowInteractByGUID = (InteractByGUID_t)0x005277B0;

typedef int(__cdecl* LUA_SpellHandler_t)(int spellId, void* pAoETargetObject, int targetGuid_Low, int targetGuid_High,
                                         char suppressErrors);

// Создаем указатель на функцию с ее реальным адресом в памяти
const LUA_SpellHandler_t CastSpell_Lua_Or_Handler = (LUA_SpellHandler_t)0x0080DA40;

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
extern VisibleObjectsHook* g_visibleObjectsHook;  // <-- Добавляем доступ к сборщику
extern volatile uintptr_t g_playerPtr;            // <-- ПОЛУЧАЕМ ДОСТУП К УКАЗАТЕЛЮ ИЗ CharacterHo

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
 * @brief (ФИНАЛЬНАЯ ВЕРСИЯ БЕЗ UNION) Читает ID всех активных аур, используя точные счетчики.
 * @details Эта функция реализует логику с двумя режимами. Она читает "умный"
 *          счетчик/флаг на смещении 0xDD0. Если он не -1, используется встроенный массив.
 *          Если он -1, используется динамический массив, а его вместимость читается
 *          со смещения 0xEE0.
 * @param pUnit Указатель на объект Unit в памяти игры.
 * @param outInfo Ссылка на структуру GameObjectInfo, куда будут записаны результаты.
 */
void ReadUnitAuras(Unit* pUnit, GameObjectInfo& outInfo)
{
    outInfo.auraCount = 0;
    if (!pUnit) return;

    AuraSlot* auraArray = nullptr;
    int aurasToScan = 0;  // Количество слотов для сканирования

    // --- ШАГ 1: Проверяем режим работы, используя твою структуру ---
    if (pUnit->m_auraCount_or_Flag != -1)
    {
        // РЕЖИМ 1: "Простой"
        // Указатель на ауры - это просто адрес поля m_auras
        auraArray = pUnit->m_auras;

        // Используем точный счетчик из этого же поля
        aurasToScan = pUnit->m_auraCount_or_Flag;
    }
    else
    {
        // РЕЖИМ 2: "Сложный"
        // Читаем указатель на динамический массив. Он лежит по смещению 0xC58.
        // Это то же самое место, где в "простом" режиме начинается m_auras[1].
        auraArray = *(AuraSlot**)((char*)pUnit + 0xC58);

        // ЧИТАЕМ НАСТОЯЩУЮ ВМЕСТИМОСТЬ МАССИВА!
        // Используем наше поле m_auras_capacity
        aurasToScan = pUnit->m_auras_capacity;
    }

    if (!auraArray) return;

    // --- ШАГ 2: В цикле с ТОЧНОЙ границей читаем ID спеллов ---
    for (int i = 0; i < aurasToScan; ++i)
    {
        // Предохранитель, чтобы не переполнить НАШ буфер в SharedData
        if (outInfo.auraCount >= MAX_AURAS_PER_UNIT)
        {
            break;
        }

        try
        {
            AuraSlot& slot = auraArray[i];

            // Наш финальный, самый простой и надежный фильтр
            if (slot.spellId != 0)
            {
                outInfo.auras[outInfo.auraCount] = slot.spellId;
                outInfo.auraCount++;
            }
        }
        catch (...)
        {
            // Аварийный выход, если что-то пошло не так
            OutputDebugStringA("MDBot_Client: Exception caught while reading aura, stopping.");
            break;
        }
    }
}

/**
 * @brief Читает глобальный список кулдаунов персонажа и заполняет PlayerData.
 * @details Проходит по связанному списку кулдаунов, начиная со статического указателя,
 *          и фильтрует только активные на данный момент кулдауны.
 * @param playerData Ссылка на структуру данных игрока, куда будут записаны результаты.
 */
void ReadPlayerCooldowns(PlayerData& playerData)
{
    // --- ШАГ 1: ПОДГОТОВКА ---
    // В начале каждого цикла мы сбрасываем все данные. Это гарантирует,
    // что мы не будем работать с "протухшей" информацией с прошлого тика.
    playerData.activeCooldownCount = 0;
    playerData.isGcdActive = false;

    // Статические адреса, которые мы нашли в клиенте.
    const uintptr_t POINTER_TO_LAST_NODE = 0x00D3F5B0;
    const uintptr_t GAME_TICK_COUNT_ADDR = 0x00B1D618;

    // Используем __try/__except для защиты от падений, если игра изменит
    // структуру списка в момент нашего чтения.
    __try
    {
        // Читаем текущее время игры ОДИН РАЗ, чтобы все расчеты в этом цикле
        // были согласованы.
        uint32_t currentTime = *(uint32_t*)GAME_TICK_COUNT_ADDR;

        // Получаем адрес самого нового узла в списке.
        uintptr_t pLastNodeAddress = *(uintptr_t*)POINTER_TO_LAST_NODE;

        // Проверяем, не пуст ли список. Если указатель указывает сам на себя,
        // значит, активных кулдаунов нет.
        if (pLastNodeAddress == POINTER_TO_LAST_NODE || pLastNodeAddress == 0)
        {
            return;  // Выходим из функции, данные уже сброшены в 'false' и '0'.
        }

        // --- ШАГ 2: ОБХОД СПИСКА ---
        CooldownInfoNode* pCurrent = (CooldownInfoNode*)pLastNodeAddress;
        int safetyCounter = 0;  // Предохранитель от бесконечных циклов.

        // Идем по списку НАЗАД (через pPrev), пока не вернемся к "голове".
        while (pCurrent != nullptr && (uintptr_t)pCurrent != POINTER_TO_LAST_NODE && safetyCounter < 50)
        {
            // Внутренний __try для защиты от чтения одного "испорченного" узла.
            __try
            {
                // Сохраняем указатель на следующий узел перед тем, как работать с текущим.
                // Это позволяет нам продолжить обход, даже если pCurrent станет невалидным.
                CooldownInfoNode* pPrevNode = pCurrent->pPrev;

                // --- ЗАДАЧА А: ИЩЕМ БОЕВОЙ ГЛОБАЛЬНЫЙ КУЛДАУН ---
                // Мы ищем специальный узел-маркер ГКД по его "магическому числу" - 133.
                // Также проверяем, что у него есть длительность.
                if (pCurrent->TypeGlobalCooldown == 133 && pCurrent->globalCooldown > 0)
                {
                    // Если нашли, вычисляем прошедшее время и сравниваем с длительностью.
                    if ((currentTime - pCurrent->startTime) < pCurrent->globalCooldown)
                    {
                        // Если ГКД еще не прошел, выставляем флаг для "мозга" бота.
                        playerData.isGcdActive = true;
                    }
                }

                // --- ЗАДАЧА Б: ИЩЕМ ОБЫЧНЫЕ КУЛДАУНЫ (личные и категорийные) ---
                uint32_t duration = 0;
                // Сначала проверяем личный кулдаун.
                if (pCurrent->spellCooldown > 0)
                {
                    duration = pCurrent->spellCooldown;
                }
                // Если его нет, проверяем категорийный.
                else if (pCurrent->categoryCooldown > 0)
                {
                    duration = pCurrent->categoryCooldown;
                }

                // Если мы нашли узел с обычным кулдауном, и он еще не прошел...
                if (duration > 0 && (currentTime - pCurrent->startTime) < duration)
                {
                    // ...добавляем его в наш массив для "мозга" бота.
                    if (playerData.activeCooldownCount < MAX_PLAYER_COOLDOWNS)
                    {
                        SpellCooldown& cd = playerData.activeCooldowns[playerData.activeCooldownCount];
                        cd.spellId = pCurrent->spellId;
                        cd.startTime = pCurrent->startTime;
                        cd.duration = duration;
                        playerData.activeCooldownCount++;
                    }
                }

                // Переходим к следующему (предыдущему в списке) узлу.
                pCurrent = pPrevNode;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Если один из узлов оказался "битым", просто прерываем цикл,
                // чтобы не рисковать дальше. Собранные данные все еще будут полезны.
                char debugMsg[256];
                sprintf_s(debugMsg, "MDBot_Client: CRITICAL - Access violation at node 0x%p. Aborting scan.", pCurrent);
                OutputDebugStringA(debugMsg);
                break;
            }
            safetyCounter++;
        }
        /*char debugMsg[256];
        sprintf_s(debugMsg, "MDBot_Client: Scan Complete -> GCD Active: %s, Found Cooldowns: %d",
                  (playerData.isGcdActive ? "Yes" : "No"), playerData.activeCooldownCount);
        OutputDebugStringA(debugMsg);
        */
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Если произошел сбой на самом начальном этапе (например, игра выгружается),
        // гарантируем, что у "мозга" будут чистые данные.
        OutputDebugStringA("MDBot_Client: CRITICAL - Exception in initial read phase. Cooldown data is invalid.");
        playerData.activeCooldownCount = 0;
        playerData.isGcdActive = false;
    }
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

            case ClientCommandType::FaceTarget:
            {
                // 1. Разбиваем 64-битный GUID на две 32-битные части
                uint32_t guid_low = (uint32_t)(cmd.targetGuid & 0xFFFFFFFF);
                uint32_t guid_high = (uint32_t)(cmd.targetGuid >> 32);

                // 2. Записываем обе части в соответствующие ячейки памяти
                *(uint32_t*)CtmOffsets::CTM_GUID_LOW = guid_low;
                *(uint32_t*)CtmOffsets::CTM_GUID_HIGH = guid_high;

                // 3. Устанавливаем тип действия "Повернуться к цели"
                *(int*)CtmOffsets::CTM_ACTION_TYPE = static_cast<int>(CtmActionType::FACE_TARGET);

                // Для отладки
                sprintf_s(debugMsg, "MDBot_Client: Executed FaceTarget command for GUID: %llX", cmd.targetGuid);
                OutputDebugStringA(debugMsg);
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

            info.guid = worldObject->guid;
            info.type = worldObject->objectType;
            info.baseAddress = objectPtr;
            info.entryId = getEntryIdFromGuid(info.guid, info.type);

            switch (info.type)
            {
                case GameObjectType::Unit:
                case GameObjectType::Player:
                {
                    Unit* unit = reinterpret_cast<Unit*>(objectPtr);
                    info.orientation = unit->m_movement.orientation;
                    info.position = unit->m_movement.position;
                    // Всегда проверяем указатель, чтобы избежать вылета игры!
                    if (unit->pUnitProperties)
                    {
                        info.health = unit->pUnitProperties->currentHealth;
                        info.maxHealth = unit->pUnitProperties->maxHealth;
                        info.mana = unit->pUnitProperties->currentMana;
                        info.maxMana = unit->pUnitProperties->maxMana;
                        info.level = unit->pUnitProperties->level;
                        info.flags = unit->pUnitProperties->flags;  // Заполняем новое поле!

                        uint64_t high = unit->pUnitProperties->targetGuid_high;
                        uint64_t low = unit->pUnitProperties->targetGuid_low;
                        info.targetGuid = (high << 32) | low;
                    }
                    else
                    {
                        // Если по какой-то причине указателя нет, обнуляем данные
                        info.health = 0;
                        info.maxHealth = 0;
                        info.mana = 0;
                        info.maxMana = 0;
                        info.level = 0;
                        info.flags = 0;
                        info.targetGuid = 0;
                    }
                    if (unit->castID != 0)
                    {
                        info.isCasting = true;
                        info.castingSpellId = unit->castSpellId;
                    }
                    else
                    {
                        info.isCasting = false;
                        info.castingSpellId = 0;
                    }
                    ReadUnitAuras(unit, info);
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

    // --- 3. ЗАПОЛНЕНИЕ ДАННЫХ ИГРОКА ---
    if (g_playerPtr != 0)
    {
        try
        {
            Unit* playerUnit = reinterpret_cast<Unit*>(g_playerPtr);
            sharedData->player.baseAddress = g_playerPtr;
            sharedData->player.guid = playerUnit->guid;
            sharedData->player.position = playerUnit->m_movement.position;
            if (playerUnit->pUnitProperties)
            {
                sharedData->player.health = playerUnit->pUnitProperties->currentHealth;
                sharedData->player.maxHealth = playerUnit->pUnitProperties->maxHealth;
                sharedData->player.mana = playerUnit->pUnitProperties->currentMana;
                sharedData->player.maxMana = playerUnit->pUnitProperties->maxMana;
                sharedData->player.level = playerUnit->pUnitProperties->level;
                sharedData->player.flags = playerUnit->pUnitProperties->flags;  // Заполняем новое поле!
            }
            else
            {
                sharedData->player.health = 0;
                sharedData->player.maxHealth = 0;
                sharedData->player.mana = 0;
                sharedData->player.maxMana = 0;
                sharedData->player.level = 0;
                sharedData->player.flags = 0;
            }
        }
        catch (...)
        {
            OutputDebugStringA("MDBot_Client: CRITICAL - Exception caught while reading player data.");
            memset(&sharedData->player, 0, sizeof(PlayerData));
        }
        ReadPlayerCooldowns(sharedData->player);
    }
    else
    {
        memset(&sharedData->player, 0, sizeof(PlayerData));
    }
}