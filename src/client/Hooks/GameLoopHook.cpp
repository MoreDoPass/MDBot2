#include "GameLoopHook.h"
#include <windows.h>
#include "core/Memory/SharedMemoryConnector.h"  // <-- Подключаем коннектор
#include "shared/Data/SharedData.h"             // <-- Подключаем структуры
#include "VisibleObjectsHook.h"
#include <set>  // <-- ИСПРАВЛЕНИЕ: Подключаем заголовок для std::set

extern SharedMemoryConnector* g_sharedMemory;
extern VisibleObjectsHook* g_visibleObjectsHook;  // <-- Добавляем доступ к сборщику

// Передаем в конструктор базового класса наш целевой адрес
GameLoopHook::GameLoopHook() : InlineHook(0x728A27) {}

void GameLoopHook::handler(const Registers* regs)
{
    // Проверяем, что оба глобальных объекта существуют
    if (!g_sharedMemory || !g_visibleObjectsHook)
    {
        return;
    }

    // 1. Получаем список уникальных указателей на объекты, собранных с момента последней проверки
    std::set<uintptr_t> objectPointers = g_visibleObjectsHook->getAndClearObjects();

    // Если новых объектов нет, ничего не делаем
    if (objectPointers.empty())
    {
        // Можно отправлять только данные игрока, если нужно, но пока пропустим
        return;
    }

    // 2. Создаем структуру для отправки (обязательно инициализируем нулями)
    SharedData dataToSend{};

    // 3. Заполняем данные игрока (пока статически, потом будешь читать из памяти)
    dataToSend.player.health = 1234;
    dataToSend.player.maxHealth = 5678;
    dataToSend.player.position = {1.0f, 2.0f, 3.0f};

    // 4. Заполняем данные по видимым объектам
    dataToSend.visibleObjectCount = 0;
    for (uintptr_t objectPtr : objectPointers)
    {
        if (dataToSend.visibleObjectCount >= MAX_VISIBLE_OBJECTS)
        {
            break;  // Превысили лимит в нашем массиве, выходим
        }

        // !!! ВАЖНО !!!
        // Здесь нужно будет читать данные из памяти игры по указателю objectPtr.
        // Тебе нужно будет найти смещения (offsets) для нужных полей.
        // Например (адреса вымышленные!):
        // uint64_t guid = *(uint64_t*)(objectPtr + 0x30);
        // uint32_t type = *(uint32_t*)(objectPtr + 0x14);
        // Vec3* pos = (Vec3*)(objectPtr + 0x9B8);

        // Сейчас для теста заполним статическими данными + указателем для отладки
        GameObjectInfo& info = dataToSend.visibleObjects[dataToSend.visibleObjectCount];
        info.guid = objectPtr;                             // Для отладки пока используем указатель как GUID
        info.type = 1;                                     // Тип 1 (например, Unit)
        info.position = {(float)objectPtr, 20.0f, 30.0f};  // Используем указатель, чтобы видеть, что данные меняются

        dataToSend.visibleObjectCount++;
    }

    // 5. Отправляем все данные одним пакетом через общую память
    g_sharedMemory->write(dataToSend);

    // Трамплин вызовется автоматически.
}