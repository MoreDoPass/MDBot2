#include "FindObjectByIdAction.h"
#include "Shared/Data/SharedData.h"  // Нужен для GameObjectInfo
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logFindById, "mdbot.bt.action.findbyid")

/**
 * @brief Конструктор.
 * @details Принимает вектор ID и сразу же копирует его содержимое в std::set для
 *          быстрого последующего поиска. Использование `std::set` позволяет
 *          проверять наличие ID за время O(log n) вместо O(n) для вектора.
 * @param idsToFind Вектор с Entry ID объектов, которые нужно искать.
 */
FindObjectByIdAction::FindObjectByIdAction(std::vector<int> idsToFind)
    : m_idsToFind(idsToFind.begin(), idsToFind.end())  // Сразу копируем в set для скорости
{
    // Тело конструктора может быть пустым, вся работа сделана в списке инициализации.
}

/**
 * @brief Основная логика "навыка".
 * @details Получает у GameObjectManager все видимые объекты, перебирает их
 *          и ищет тот, чей entryId совпадает с одним из ID в нашем списке.
 *          Среди всех совпадений выбирает ближайший к персонажу.
 * @param context Контекст дерева поведения.
 * @return Success, если цель найдена; Failure, если нет.
 */
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
    const GameObjectInfo* closestObject = nullptr;
    float minDistanceSq = 999999.0f;

    Vector3 myPosition = context.character->GetPosition();

    for (const GameObjectInfo* objInfo : allObjects)
    {
        // --- ГЛАВНАЯ ПРОВЕРКА: Это тот ID, который мы ищем? ---
        // У objInfo есть поле entryId, доступ к которому теперь корректен.
        if (m_idsToFind.count(objInfo->entryId))
        {
            // У objInfo всегда есть position, никаких dynamic_cast не нужно.
            const Vector3& objPosition = objInfo->position;

            float distanceSq = myPosition.DistanceSq(objPosition);
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

    qCDebug(logFindById) << "No objects with specified IDs found in visible range.";
    return NodeStatus::Failure;
}