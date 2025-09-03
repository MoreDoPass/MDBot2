#include "FindGameObjectByTypeAction.h"
#include "shared/Structures/WorldObject.h"  // Нужен для базовых полей
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logFindAction, "mdbot.bt.action.findobject")

FindGameObjectByTypeAction::FindGameObjectByTypeAction(GameObjectType typeToFind) : m_typeToFind(typeToFind) {}

NodeStatus FindGameObjectByTypeAction::tick(BTContext& context)
{
    auto gom = context.gameObjectManager;
    if (!gom)
    {
        qCCritical(logFindAction) << "GameObjectManager is null in BTContext!";
        return NodeStatus::Failure;
    }

    // Теперь мы просим у "шпиона" объекты нужного нам типа
    auto objects = gom->getObjectsByType(m_typeToFind);
    GameObject* closestObject = nullptr;
    float minDistanceSq = 999999.0f;

    Vector3 myPosition = context.character->GetPosition();

    // --- ИЗМЕНЕНИЯ ЗДЕСЬ ---
    for (auto worldObj : objects)
    {
        // 1. Мы БЕЗОПАСНО преобразуем WorldObject* в GameObject*
        GameObject* gameObj = static_cast<GameObject*>(worldObj);

        // 2. Теперь мы можем получить доступ к полю 'position',
        //    которое есть у GameObject
        float distanceSq = myPosition.DistanceSq(gameObj->position);
        if (distanceSq < minDistanceSq)
        {
            minDistanceSq = distanceSq;
            closestObject = gameObj;  // Теперь типы совпадают!
        }
    }

    if (closestObject)
    {
        context.currentTargetGuid = closestObject->guid;
        qCInfo(logFindAction) << "Найдена цель (Type:" << static_cast<int>(m_typeToFind) << "). GUID:" << Qt::hex
                              << context.currentTargetGuid;
        return NodeStatus::Success;
    }

    // --- ДОБАВЛЕНО ЛОГИРОВАНИЕ ---
    // Если мы дошли до сюда, значит цикл завершился, а closestObject все еще nullptr.
    // Это значит, что ни одного объекта нужного типа в зоне видимости нет.
    qCDebug(logFindAction) << "No objects of type" << static_cast<int>(m_typeToFind) << "found in visible range.";
    return NodeStatus::Failure;
}