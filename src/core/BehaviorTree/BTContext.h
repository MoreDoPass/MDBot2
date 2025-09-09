#pragma once

// Подключаем заголовки менеджеров, к которым "навыкам" понадобится доступ.
// Пути основаны на структуре твоего проекта.
#include "core/Bot/Character/Character.h"
#include "core/Bot/GameObjectManager/GameObjectManager.h"
#include "core/Bot/Movement/MovementManager.h"
#include "core/Bot/Settings/BotSettings.h"       // <-- ДОБАВЛЕНО: нужен для BotStartSettings
#include "core/Bot/Profiles/GatheringProfile.h"  // <-- ДОБАВЛЕНО: нужен для GatheringProfile
#include "Shared/Utils/Vector.h"                 // <-- ДОБАВЛЕНО: нужен для Vec3
#include <memory>                                // <-- ДОБАВЛЕНО: нужен для std::shared_ptr
#include <map>                                   // <-- ДОБАВЛЕНО
#include <QDateTime>                             // <-- ДОБАВЛЕНО

class ProfileManager;

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
    ProfileManager* profileManager = nullptr;

    // --- Настройки ---
    // Копия настроек, с которыми был запущен бот.
    // Нужна, чтобы узлы дерева могли принимать решения на их основе.
    BotStartSettings settings;  // <-- ДОБАВЛЕНО

    // Временные данные, которые "навыки" могут использовать для общения.
    // Например, сюда "навык поиска" положит GUID цели,
    // а "навык атаки" отсюда его заберет.
    uint64_t currentTargetGuid = 0;

    // Указатель на загруженный и распарсенный профиль
    std::shared_ptr<GatheringProfile> gatheringProfile;  // <-- ДОБАВЛЕНО

    /// @brief Позиция цели, если целью являются просто координаты (точка на маршруте).
    Vector3 currentTargetPosition;  // <-- ДОБАВЛЕНО

    /// @brief Индекс текущей точки в маршруте gatheringProfile->path.
    size_t currentPathIndex = 0;  // <-- ДОБАВЛЕНО

    /// @brief Счетчик тиков, которые нужно подождать на точке маршрута.
    int waypointWaitCounter = 0;

    /**
     * @brief Временный черный список для объектов.
     * @details Ключ - GUID объекта, значение - время, до которого объект следует игнорировать.
     *          Это нужно, чтобы избежать циклических попыток сбора объекта, если, например,
     *          рядом постоянно находится другой игрок.
     */
    std::map<uint64_t, QDateTime> objectBlacklist;
};