#include "MoveToTargetAction.h"
#include "core/BehaviorTree/BTNode.h"
#include "shared/Structures/GameObject.h"
#include "shared/Structures/Unit.h"
#include "shared/Structures/Player.h"  // Нам нужен и Player
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logMoveToAction, "mdbot.bt.action.moveto")

NodeStatus MoveToTargetAction::tick(BTContext& context)
{
    if (context.currentTargetGuid == 0)
    {
        qCWarning(logMoveToAction) << "MoveToTargetAction failed: currentTargetGuid is 0.";
        return NodeStatus::Failure;
    }

    auto gom = context.gameObjectManager;
    auto movementManager = context.movementManager;
    if (!gom || !movementManager)
    {
        qCCritical(logMoveToAction) << "Manager is null in BTContext!";
        return NodeStatus::Failure;
    }

    WorldObject* targetObject = gom->getObjectByGuid(context.currentTargetGuid);
    if (!targetObject)
    {
        qCWarning(logMoveToAction) << "MoveToTargetAction failed: Can't find object with GUID:" << Qt::hex
                                   << context.currentTargetGuid;
        context.currentTargetGuid = 0;
        return NodeStatus::Failure;
    }

    // --- НОВАЯ, ПРАВИЛЬНАЯ ЛОГИКА ПОЛУЧЕНИЯ ПОЗИЦИИ ---
    Vector3 targetPosition;
    bool positionFound = false;

    // Проверяем тип объекта, который нам дала игра
    switch (targetObject->objectType)
    {
        case GameObjectType::GameObject:
        {
            // Мы уверены, что это GameObject, поэтому static_cast безопасен
            GameObject* gameObj = static_cast<GameObject*>(targetObject);
            targetPosition = gameObj->position;
            positionFound = true;
            break;
        }
        case GameObjectType::Unit:
        {
            // Это может быть моб или NPC
            Unit* unit = static_cast<Unit*>(targetObject);
            targetPosition = unit->position;
            positionFound = true;
            break;
        }
        case GameObjectType::Player:
        {
            // Это игрок. У него структура как у Unit.
            Player* player = static_cast<Player*>(targetObject);
            targetPosition = player->position;
            positionFound = true;
            break;
        }
        default:
            // Для других типов (Item, Corpse и т.д.) у нас нет позиции
            qCWarning(logMoveToAction) << "MoveToTargetAction failed: Target type"
                                       << static_cast<int>(targetObject->objectType) << "has no position.";
            return NodeStatus::Failure;
    }

    if (!positionFound)
    {
        // На всякий случай, хотя default в switch должен это покрывать
        return NodeStatus::Failure;
    }

    // --- Дальнейшая логика остается без изменений ---
    if (context.character->GetPosition().DistanceSq(targetPosition) < 25.0f)
    {
        qCInfo(logMoveToAction) << "Already at target. Success.";
        return NodeStatus::Success;
    }

    movementManager->moveTo(targetPosition);
    qCInfo(logMoveToAction) << "MoveTo command sent for target" << Qt::hex << context.currentTargetGuid;

    return NodeStatus::Running;
}