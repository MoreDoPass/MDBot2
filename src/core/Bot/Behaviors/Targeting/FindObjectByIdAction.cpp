#include "FindObjectByIdAction.h"
#include "shared/Structures/WorldObject.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logFindById, "mdbot.bt.action.findbyid")

FindObjectByIdAction::FindObjectByIdAction(std::vector<int> idsToFind)
    : m_idsToFind(idsToFind.begin(), idsToFind.end())  // Сразу копируем в set для скорости
{
}

NodeStatus FindObjectByIdAction::tick(BTContext& context)
{
    if (m_idsToFind.empty())
    {
        qCWarning(logFindById) << "List of IDs to find is empty. Nothing to do.";
        return NodeStatus::Failure;
    }

    auto gom = context.gameObjectManager;
    if (!gom)
    {
        qCCritical(logFindById) << "GameObjectManager is null in BTContext!";
        return NodeStatus::Failure;
    }

    // Получаем ВСЕ видимые объекты, чтобы было из чего выбирать
    auto allObjects = gom->getAllObjects();
    WorldObject* closestObject = nullptr;
    float minDistanceSq = 999999.0f;

    Vector3 myPosition = context.character->GetPosition();

    for (auto worldObj : allObjects)
    {
        // --- ГЛАВНАЯ ПРОВЕРКА: Это тот ID, который мы ищем? ---
        if (m_idsToFind.count(worldObj->entryId))
        {
            // Получаем позицию, только если ID нам подходит
            Vector3 objPosition;
            if (auto* unit = dynamic_cast<Unit*>(worldObj))
            {
                objPosition = unit->position;
            }
            else if (auto* gameObj = dynamic_cast<GameObject*>(worldObj))
            {
                objPosition = gameObj->position;
            }
            else
            {
                continue;  // У объекта нет позиции
            }

            float distanceSq = myPosition.DistanceSq(objPosition);
            if (distanceSq < minDistanceSq)
            {
                minDistanceSq = distanceSq;
                closestObject = worldObj;
            }
        }
    }

    if (closestObject)
    {
        context.currentTargetGuid = closestObject->guid;
        qCInfo(logFindById) << "Found target object. GUID:" << Qt::hex << context.currentTargetGuid
                            << "EntryID:" << Qt::dec << closestObject->entryId;
        return NodeStatus::Success;
    }

    qCDebug(logFindById) << "No objects with specified IDs found in visible range.";
    return NodeStatus::Failure;
}