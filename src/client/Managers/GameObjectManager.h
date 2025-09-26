#pragma once
#include "shared/Data/SharedData.h"
#include "shared/Structures/Player.h"

// Прямое объявление, чтобы не включать лишний заголовок.
// Мы просто обещаем компилятору, что такой класс где-то есть.
class VisibleObjectsHook;

class GameObjectManager
{
   public:
    // Конструктор, который принимает свою единственную зависимость.
    GameObjectManager(VisibleObjectsHook* collectorHook);

    // Единственный публичный метод, который будет "дергать" MainLoopHook.
    void collect(SharedData* sharedData, uintptr_t playerPtrToIgnore);

    /**
     * @brief Читает ID всех активных аур (бафов/дебафов), используя точные счетчики.
     * @details Эта функция реализует логику с двумя режимами. Она читает "умный"
     *          счетчик/флаг на смещении 0xDD0. Если он не -1, используется встроенный массив.
     *          Если он -1, используется динамический массив, а его вместимость читается
     *          со смещения 0xEE0.
     * @param pUnit Указатель на объект Unit в памяти игры.
     * @param outInfo Ссылка на структуру GameObjectInfo, куда будут записаны результаты.
     */
    static void readUnitAuras(Unit* pUnit, int32_t* outAuraIds, int32_t& outAuraCount, int32_t maxAuras);

   private:
    static int32_t getEntryIdFromGuid(uint64_t guid, GameObjectType type);

    // Указатель на наш "поставщик" сырых данных (указателей на объекты).
    VisibleObjectsHook* m_collectorHook;
};