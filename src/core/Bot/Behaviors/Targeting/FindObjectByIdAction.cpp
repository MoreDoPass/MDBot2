#include "FindObjectByIdAction.h"
#include "Shared/Data/SharedData.h"
#include "core/BlacklistManager/BlacklistManager.h"
#include <QLoggingCategory>
#include <QDateTime>

Q_LOGGING_CATEGORY(logFindById, "mdbot.bt.action.findbyid")

FindObjectByIdAction::FindObjectByIdAction(std::vector<int> idsToFind) : m_idsToFind(idsToFind.begin(), idsToFind.end())
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

    const auto allObjects = gom->getAllObjects();
    const GameObjectInfo* closestObject = nullptr;
    float minDistanceSq = 999999.0f;
    const QDateTime currentTime = QDateTime::currentDateTime();

    const Vector3 myPosition = context.character->GetPosition();

    for (const GameObjectInfo* objInfo : allObjects)
    {
        if (m_idsToFind.count(objInfo->entryId))
        {
            // Используем простой вызов через точку. Он быстрый и безопасный.
            if (BlacklistManager::instance().contains(objInfo->guid))
            {
                continue;
            }

            auto it = context.objectBlacklist.find(objInfo->guid);
            if (it != context.objectBlacklist.end())
            {
                if (it->second > currentTime)
                {
                    qCDebug(logFindById) << "Object" << Qt::hex << objInfo->guid
                                         << "is in temporary blacklist. Skipping.";
                    continue;
                }
                else
                {
                    qCDebug(logFindById) << "Object" << Qt::hex << objInfo->guid
                                         << "removed from temporary blacklist (expired).";
                    context.objectBlacklist.erase(it);
                }
            }

            const Vector3& objPosition = objInfo->position;
            const float distanceSq = myPosition.DistanceSq(objPosition);
            if (distanceSq < minDistanceSq)
            {
                minDistanceSq = distanceSq;
                closestObject = objInfo;
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

    qCDebug(logFindById) << "No valid (not blacklisted) objects with specified IDs found.";
    return NodeStatus::Failure;
}