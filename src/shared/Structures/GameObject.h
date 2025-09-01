#pragma once
#include "WorldObject.h"
#include "shared/Utils/Vector.h"

#pragma pack(push, 1)

/**
 * @struct GameObject
 * @brief Расширяет WorldObject, добавляя поля для "неживых" объектов (руда, трава, сундуки).
 * @details Наследуется от WorldObject. Важно отметить, что смещение позиции (0xE8)
 *          у этого типа объектов отличается от смещения у Unit (0x798).
 */
struct GameObject : public WorldObject
{
    // C++ автоматически разместил здесь WorldObject размером 0xD0 байт.

    // 1. Заполнитель от конца WorldObject (0xD0) до поля position (0xE8)
    char _pad_to_position[0xE8 - sizeof(WorldObject)];

    /// @brief [смещение 0xE8] Позиция объекта в 3D мире (X, Y, Z).
    Vector3 position;

    // На данный момент другие поля GameObject нам не нужны.
    // Если в будущем понадобятся, мы добавим их здесь,
    // используя тот же принцип с паддингом.
};

#pragma pack(pop)