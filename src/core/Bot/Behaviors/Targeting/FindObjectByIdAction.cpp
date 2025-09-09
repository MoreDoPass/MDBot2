#include "FindObjectByIdAction.h"
#include "Shared/Data/SharedData.h"  // Нужен для GameObjectInfo
#include <QLoggingCategory>
#include <QDateTime>  // <-- ДОБАВЛЕНО

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
    const auto allObjects = gom->getAllObjects();
    const GameObjectInfo* closestObject = nullptr;
    float minDistanceSq = 999999.0f;
    const QDateTime currentTime = QDateTime::currentDateTime();  // Получаем текущее время один раз

    const Vector3 myPosition = context.character->GetPosition();

    for (const GameObjectInfo* objInfo : allObjects)
    {
        // --- ПРОВЕРКА №1: Это тот ID, который мы ищем? ---
        if (m_idsToFind.count(objInfo->entryId))
        {
            // --- НОВАЯ ПРОВЕРКА №2: Нет ли этого объекта в черном списке? ---
            auto it = context.objectBlacklist.find(objInfo->guid);
            if (it != context.objectBlacklist.end())
            {
                // Объект найден в списке. Проверяем, не истекло ли время.
                if (it->second > currentTime)
                {
                    qCDebug(logFindById) << "Object" << Qt::hex << objInfo->guid << "is in blacklist. Skipping.";
                    continue;  // Переходим к следующему объекту
                }
                else
                {
                    // Время истекло, удаляем из списка для очистки
                    qCDebug(logFindById) << "Object" << Qt::hex << objInfo->guid << "removed from blacklist (expired).";
                    context.objectBlacklist.erase(it);
                }
            }

            // --- ПРОВЕРКА №3: Расстояние ---
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