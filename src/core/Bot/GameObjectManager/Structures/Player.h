#pragma once

#include "Unit.h"

#pragma pack(push, 1)

/**
 * @struct Player
 * @brief Структура для игрока.
 * @details Наследуется от Unit и добавляет специфичные для игрока поля.
 */
struct Player : public Unit
{
    // Пока что у игроков нет дополнительных полей, которые мы знаем.
    // В будущем здесь могут быть поля вроде "опыт", "уровень отдыха" и т.д.
};

#pragma pack(pop)