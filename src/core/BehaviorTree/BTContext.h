#pragma once

// Подключаем заголовки менеджеров, к которым "навыкам" понадобится доступ.
// Пути основаны на структуре твоего проекта.
#include "core/Bot/Character/Character.h"
#include "core/Bot/GameObjectManager/GameObjectManager.h"
#include "core/Bot/Movement/MovementManager.h"

/**
 * @brief Класс-контейнер, который передается каждому узлу дерева.
 * @details Он предоставляет доступ ко всем системам бота и служит
 *          "доской объявлений" для обмена данными между узлами.
 */
class BTContext
{
   public:
    // Указатели на главные менеджеры бота
    Character* character = nullptr;
    GameObjectManager* gameObjectManager = nullptr;
    MovementManager* movementManager = nullptr;

    // Временные данные, которые "навыки" могут использовать для общения.
    // Например, сюда "навык поиска" положит GUID цели,
    // а "навык атаки" отсюда его заберет.
    uint64_t currentTargetGuid = 0;
};