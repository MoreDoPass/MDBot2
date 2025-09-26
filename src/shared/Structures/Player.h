#pragma once
#include "Unit.h"  // Включаем родительский класс

#pragma pack(push, 1)

/**
 * @struct Player
 * @brief Представляет объект игрока.
 * @details Наследуется от Unit и добавляет поля, специфичные для игрока.
 *          Для наших текущих задач все необходимые поля (HP, позиция и т.д.)
 *          уже содержатся в базовых классах WorldObject и Unit.
 *          Мы создаем эту структуру для полноты иерархии и для будущего
 *          расширения, если нам понадобятся специфичные для игрока поля
 *          (например, опыт, таланты и т.д.).
 */
struct Player : public Unit
{
    char data[2572];
    int something_15;
    int pBasicContainer;  // 18F4
    int guid_copy;        // 18FC
    char data2[3904];
};

#pragma pack(pop)