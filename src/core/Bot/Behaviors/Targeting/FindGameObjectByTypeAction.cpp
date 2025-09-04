#include "FindGameObjectByTypeAction.h"
#include "Shared/Data/SharedData.h"  // Нужен для GameObjectInfo
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logFindAction, "mdbot.bt.action.findobject")

FindGameObjectByTypeAction::FindGameObjectByTypeAction(GameObjectType typeToFind) : m_typeToFind(typeToFind) {}

/**
 * @brief Основная логика "навыка".
 * @details Запрашивает у GameObjectManager все объекты нужного типа,
 *          находит ближайший к персонажу и записывает его GUID в контекст.
 * @param context Контекст дерева поведения.
 * @return Success, если цель найдена; Failure, если нет.
 */
NodeStatus FindGameObjectByTypeAction::tick(BTContext& context)
{
    auto gom = context.gameObjectManager;
    if (!gom)
    {
        qCCritical(logFindAction) << "GameObjectManager is null in BTContext!";
        return NodeStatus::Failure;
    }

    // getObjectsByType теперь возвращает std::vector<const GameObjectInfo*>
    auto objects = gom->getObjectsByType(m_typeToFind);
    const GameObjectInfo* closestObject = nullptr;
    float minDistanceSq = 999999.0f;

    Vector3 myPosition = context.character->GetPosition();

    for (const GameObjectInfo* objInfo : objects)
    {
        // У objInfo всегда есть position, касты не нужны
        float distanceSq = myPosition.DistanceSq(objInfo->position);
        if (distanceSq < minDistanceSq)
        {
            minDistanceSq = distanceSq;
            closestObject = objInfo;
        }
    }

    if (closestObject)
    {
        // Записываем GUID найденной цели в контекст для следующих узлов дерева
        context.currentTargetGuid = closestObject->guid;
        qCInfo(logFindAction) << "Found target (Type:" << static_cast<int>(m_typeToFind) << "). GUID:" << Qt::hex
                              << context.currentTargetGuid << "EntryID:" << Qt::dec << closestObject->entryId;
        return NodeStatus::Success;
    }

    qCDebug(logFindAction) << "No objects of type" << static_cast<int>(m_typeToFind) << "found in visible range.";
    return NodeStatus::Failure;
}