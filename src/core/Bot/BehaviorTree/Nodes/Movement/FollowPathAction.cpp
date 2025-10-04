// ФАЙЛ: src/core/Bot/BehaviorTree/Nodes/Movement/FollowPathAction.cpp

#include "FollowPathAction.h"
#include "core/BehaviorTree/BTContext.h"  // Подключаем полный BTContext, чтобы знать о GrindingProfile
#include "core/Bot/BehaviorTree/Profiles/GrindingProfile.h"  // И сам GrindingProfile
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logFollowPath, "mdbot.bt.action.followpath")

NodeStatus FollowPathAction::tick(BTContext& context)
{
    // Указатель на вектор с точками маршрута. Инициализируем как nullptr.
    const std::vector<Vector3>* path = nullptr;
    // Ссылка на индекс текущей точки. Инициализируем через временную переменную.
    size_t* pathIndexPtr = nullptr;
    size_t tempIndex = 0;  // Временная переменная на случай, если профиля нет

    // --- НАША НОВАЯ ЛОГИКА ВЫБОРА ПРОФИЛЯ ---
    // Сначала проверяем, активен ли профиль гринда. Он имеет приоритет.
    if (context.grindingProfile && !context.grindingProfile->path.empty())
    {
        path = &context.grindingProfile->path;
        pathIndexPtr = &context.grindingPathIndex;
    }
    // Если профиля гринда нет, проверяем профиль сбора.
    else if (context.gatheringProfile && !context.gatheringProfile->path.empty())
    {
        path = &context.gatheringProfile->path;
        pathIndexPtr = &context.currentPathIndex;  // Используем старый индекс
    }
    else
    {
        // Если ни одного профиля не загружено, или они пустые.
        qCCritical(logFollowPath) << "Cannot follow path: no valid profile is loaded or path is empty.";
        return NodeStatus::Failure;
    }

    // Это нужно, чтобы получить само значение индекса, а не указатель на него.
    size_t& currentPathIndex = *pathIndexPtr;

    if (!context.character)
    {
        qCCritical(logFollowPath) << "Character is null in context.";
        return NodeStatus::Failure;
    }

    // Теперь весь остальной код работает с универсальными `path` и `currentPathIndex`
    const Vector3& currentWaypoint = (*path)[currentPathIndex];
    const Vector3& playerPosition = context.character->getPosition();

    float deltaX = playerPosition.x - currentWaypoint.x;
    float deltaY = playerPosition.y - currentWaypoint.y;
    float distanceToWaypointSq2D = (deltaX * deltaX) + (deltaY * deltaY);

    const float waypointReachedThresholdSq = 25.0f;  // 5 метров в квадрате

    if (distanceToWaypointSq2D < waypointReachedThresholdSq)
    {
        if (context.waypointWaitCounter <= 0)
        {
            qCInfo(logFollowPath) << "Waypoint" << currentPathIndex << "reached. Waiting for ~0.6 seconds...";
            context.waypointWaitCounter = 4;
        }

        context.waypointWaitCounter--;

        if (context.waypointWaitCounter > 0)
        {
            context.currentTargetPosition = Vector3();
            context.currentTargetGuid = 0;
            return NodeStatus::Success;
        }

        qCInfo(logFollowPath) << "Wait finished. Moving to the next waypoint.";
        currentPathIndex++;
        if (currentPathIndex >= path->size())
        {
            qCInfo(logFollowPath) << "End of the path reached. Looping back to the start.";
            currentPathIndex = 0;
        }
        context.waypointWaitCounter = 0;
    }

    // Устанавливаем СЛЕДУЮЩУЮ точку маршрута как цель.
    context.currentTargetPosition = (*path)[currentPathIndex];
    context.currentTargetGuid = 0;

    return NodeStatus::Success;
}