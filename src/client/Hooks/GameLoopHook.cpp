#include "GameLoopHook.h"
#include <windows.h>
#include "core/Memory/SharedMemoryConnector.h"  // <-- Подключаем коннектор
#include "shared/Data/SharedData.h"             // <-- Подключаем структуры
#include "VisibleObjectsHook.h"
#include <set>  // <-- ИСПРАВЛЕНИЕ: Подключаем заголовок для std::set

#include "shared/Structures/Player.h"  // Включает Unit и WorldObject
#include "shared/Structures/GameObject.h"

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

    std::set<uintptr_t> objectPointers = g_visibleObjectsHook->getAndClearObjects();
    if (objectPointers.empty())
    {
        return;
    }

    SharedData dataToSend{};

    // TODO: Заполнять реальные данные игрока, когда найдем на него указатель.
    dataToSend.player.health = 1234;
    dataToSend.player.maxHealth = 5678;
    dataToSend.player.position = {1.0f, 2.0f, 3.0f};

    dataToSend.visibleObjectCount = 0;
    for (uintptr_t objectPtr : objectPointers)
    {
        if (dataToSend.visibleObjectCount >= MAX_VISIBLE_OBJECTS)
        {
            break;
        }

        // --- НАЧАЛО НОВОЙ ЛОГИКИ ---
        try
        {
            // 1. "Накладываем" базовый трафарет, чтобы прочитать общие поля.
            WorldObject* worldObject = reinterpret_cast<WorldObject*>(objectPtr);

            // Получаем ссылку на наш "транспортный" объект, который будем заполнять.
            GameObjectInfo& info = dataToSend.visibleObjects[dataToSend.visibleObjectCount];

            // 2. Заполняем поля, которые есть у всех.
            info.guid = worldObject->guid;
            info.type = worldObject->objectType;
            info.baseAddress = objectPtr;

            // 3. Используем switch по типу, чтобы прочитать специфичные поля.
            switch (info.type)
            {
                case GameObjectType::Unit:
                case GameObjectType::Player:
                {
                    // "Накладываем" более детальный трафарет для Unit/Player.
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
                    // "Накладываем" трафарет для руды/травы.
                    GameObject* gameObject = reinterpret_cast<GameObject*>(objectPtr);
                    info.position = gameObject->position;
                    // Другие поля (health, level и т.д.) останутся нулями.
                    break;
                }
                default:
                {
                    // Для неизвестных типов мы уже заполнили guid, type и baseAddress.
                    // Остальные поля останутся нулями. Можно ничего не делать.
                    break;
                }
            }
            dataToSend.visibleObjectCount++;
        }
        catch (...)
        {
            // Безопасность: если указатель на объект оказался "битым" и мы упали
            // при чтении, мы просто проигнорируем этот объект и перейдем к следующему.
            // В идеале здесь нужен __try/__except, но для начала и так сойдет.
            OutputDebugStringA("MDBot_Client: CRITICAL - Exception caught while reading object memory.");
        }
        // --- КОНЕЦ НОВОЙ ЛОГИКИ ---
    }

    g_sharedMemory->write(dataToSend);
}