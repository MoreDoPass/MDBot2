// ФАЙЛ: src/core/Bot/Behaviors/Movement/FollowPathAction.cpp

#include "FollowPathAction.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logFollowPath, "mdbot.bt.action.followpath")

NodeStatus FollowPathAction::tick(BTContext& context)
{
    if (!context.gatheringProfile || context.gatheringProfile->path.empty())
    {
        qCCritical(logFollowPath) << "Cannot follow path: gathering profile is not loaded or path is empty.";
        return NodeStatus::Failure;
    }

    if (!context.character)
    {
        qCCritical(logFollowPath) << "Character is null in context.";
        return NodeStatus::Failure;
    }

    const Vector3& currentWaypoint = context.gatheringProfile->path[context.currentPathIndex];
    const Vector3& playerPosition = context.character->GetPosition();

    float deltaX = playerPosition.x - currentWaypoint.x;
    float deltaY = playerPosition.y - currentWaypoint.y;
    float distanceToWaypointSq2D = (deltaX * deltaX) + (deltaY * deltaY);

    const float waypointReachedThresholdSq = 25.0f;  // 5 метров в квадрате

    if (distanceToWaypointSq2D < waypointReachedThresholdSq)
    {
        if (context.waypointWaitCounter <= 0)
        {
            // Устанавливаем таймер ожидания. 4 тика * 150 мс = 600 мс (чуть больше 0.5 сек)
            qCInfo(logFollowPath) << "Waypoint" << context.currentPathIndex << "reached. Waiting for ~0.6 seconds...";
            context.waypointWaitCounter = 3;
        }

        context.waypointWaitCounter--;

        if (context.waypointWaitCounter > 0)
        {
            // --- КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ ---
            // Пока мы ждем, мы должны ОЧИСТИТЬ цель.
            // Это заставит узлы движения ничего не делать. Бот будет стоять "афк".
            context.currentTargetPosition = Vector3();  // Устанавливаем нулевой вектор
            context.currentTargetGuid = 0;
            return NodeStatus::Success;
        }

        qCInfo(logFollowPath) << "Wait finished. Moving to the next waypoint.";
        context.currentPathIndex++;
        if (context.currentPathIndex >= context.gatheringProfile->path.size())
        {
            qCInfo(logFollowPath) << "End of the path reached. Looping back to the start.";
            context.currentPathIndex = 0;
        }
        context.waypointWaitCounter = 0;
    }

    // Устанавливаем СЛЕДУЮЩУЮ точку маршрута как цель.
    context.currentTargetPosition = context.gatheringProfile->path[context.currentPathIndex];
    context.currentTargetGuid = 0;

    return NodeStatus::Success;
}