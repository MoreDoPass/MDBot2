#include "GameObjectManager.h"
#include "client/Hooks/VisibleObjectsHook.h"
#include "shared/Structures/Player.h"  // Включает Unit и WorldObject
#include "shared/Structures/GameObject.h"
#include <windows.h>  // Для OutputDebugStringA
#include <set>

// Конструктор просто сохраняет указатель на хук-сборщик
GameObjectManager::GameObjectManager(VisibleObjectsHook* collectorHook) : m_collectorHook(collectorHook) {}

// Раньше это была статическая функция в MainLoopHook.cpp
int32_t GameObjectManager::getEntryIdFromGuid(uint64_t guid, GameObjectType type)
{
    if (type == GameObjectType::Unit || type == GameObjectType::GameObject)
    {
        return static_cast<int32_t>((guid >> 24) & 0x00FFFFFF);
    }
    return 0;
}

void GameObjectManager::readUnitAuras(Unit* pUnit, int32_t* outAuraIds, int32_t& outAuraCount, int32_t maxAuras)
{
    outAuraCount = 0;  // Сбрасываем внешний счетчик
    if (!pUnit || !outAuraIds) return;

    AuraSlot* auraArray = nullptr;
    int aurasToScan = 0;

    // ... (логика определения aurasToScan остается БЕЗ ИЗМЕНЕНИЙ) ...
    if (pUnit->m_auraCount_or_Flag != -1)
    {
        auraArray = pUnit->m_auras;
        aurasToScan = pUnit->m_auraCount_or_Flag;
    }
    else
    {
        auraArray = *(AuraSlot**)((char*)pUnit + 0xC58);
        aurasToScan = pUnit->m_auras_capacity;
    }

    if (!auraArray) return;

    for (int i = 0; i < aurasToScan; ++i)
    {
        // Используем переданный лимит
        if (outAuraCount >= maxAuras)
        {
            break;
        }

        try
        {
            if (auraArray[i].spellId != 0)
            {
                // Пишем в переданный массив по указателю
                outAuraIds[outAuraCount] = auraArray[i].spellId;
                outAuraCount++;
            }
        }
        catch (...)
        {
            break;
        }
    }
}

void GameObjectManager::collect(SharedData* sharedData, uintptr_t playerPtrToIgnore)
{
    // --- ЭТОТ КОД ПОЛНОСТЬЮ СКОПИРОВАН ИЗ БЛОКА "// --- 2. СБОР ДАННЫХ ОБ ОБЪЕКТАХ ---" ---

    // Вместо g_visibleObjectsHook теперь используем наш член класса m_collectorHook
    std::set<uintptr_t> objectPointers = m_collectorHook->getAndClearObjects();

    sharedData->visibleObjectCount = 0;
    for (uintptr_t objectPtr : objectPointers)
    {
        // Если указатель на текущий объект совпадает с указателем на нашего игрока,
        // мы просто пропускаем эту итерацию цикла и переходим к следующему объекту.
        if (objectPtr == playerPtrToIgnore)
        {
            continue;
        }

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
            // Вызываем теперь НАШ метод, а не глобальную функцию
            info.entryId = getEntryIdFromGuid(info.guid, info.type);

            switch (info.type)
            {
                case GameObjectType::Unit:
                case GameObjectType::Player:
                {
                    Unit* unit = reinterpret_cast<Unit*>(objectPtr);
                    info.orientation = unit->m_movement.orientation;
                    info.position = unit->m_movement.position;
                    if (unit->pUnitProperties)
                    {
                        info.Health = unit->pUnitProperties->currentHealth;
                        info.maxHealth = unit->pUnitProperties->maxHealth;
                        info.Mana = unit->pUnitProperties->currentMana;
                        info.maxMana = unit->pUnitProperties->maxMana;
                        info.level = unit->pUnitProperties->level;
                        info.flags = unit->pUnitProperties->flags;

                        uint64_t high = unit->pUnitProperties->targetGuid_high;
                        uint64_t low = unit->pUnitProperties->targetGuid_low;
                        info.targetGuid = (high << 32) | low;
                    }
                    else
                    {
                        info.Health = 0;
                        info.maxHealth = 0;
                        info.Mana = 0;
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
                    uint64_t autoAttackHigh = unit->autoAttackTargetGuid_high;
                    uint64_t autoAttackLow = unit->autoAttackTargetGuid_low;
                    info.autoAttackTargetGuid = (autoAttackHigh << 32) | autoAttackLow;
                    // И здесь тоже вызываем НАШ приватный метод
                    GameObjectManager::readUnitAuras(unit, info.auras, info.auraCount, MAX_AURAS_PER_UNIT);
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
}