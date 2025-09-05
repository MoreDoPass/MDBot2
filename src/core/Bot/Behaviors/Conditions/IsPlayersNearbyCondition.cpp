// МЕСТОПОЛОЖЕНИЕ: src/core/Bot/Behaviors/Conditions/IsPlayersNearbyCondition.cpp

#include "IsPlayersNearbyCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include "shared/Structures/GameObject.h"  // Для GameObjectType
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logPlayersNearby, "mdbot.bt.condition.playersnearby")

IsPlayersNearbyCondition::IsPlayersNearbyCondition(float checkRadius) : m_checkRadius(checkRadius)
{
    // В будущем здесь можно будет использовать checkRadius
}

/**
 * @brief Основная логика "условия".
 * @details Запрашивает у GameObjectManager все объекты типа Player. Если их
 *          количество больше 1 (т.е. есть кто-то кроме нас), возвращает Success.
 *          В противном случае — Failure.
 * @param context Контекст дерева поведения.
 * @return Success, если рядом есть другие игроки; Failure, если нет.
 */
NodeStatus IsPlayersNearbyCondition::tick(BTContext& context)
{
    auto gom = context.gameObjectManager;
    if (!gom)
    {
        qCCritical(logPlayersNearby) << "GameObjectManager is null in BTContext!";
        // Провал, если система не инициализирована
        return NodeStatus::Failure;
    }

    // Получаем всех видимых игроков
    auto players = gom->getObjectsByType(GameObjectType::Player);

    // Наша простая и быстрая проверка
    if (players.size() > 1)
    {
        qCDebug(logPlayersNearby) << "Found" << players.size()
                                  << "players nearby (including self). Other players DETECTED. Result: Success.";
        // Найдено больше одного игрока. Значит, рядом кто-то есть.
        return NodeStatus::Success;
    }

    qCDebug(logPlayersNearby) << "Found" << players.size()
                              << "players nearby. No other players detected. Result: Failure.";
    // Найден только один игрок (это мы) или ноль. Значит, мы одни.
    return NodeStatus::Failure;
}