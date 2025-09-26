#include "FindAggressorAction.h"
#include "core/BehaviorTree/BTContext.h"
#include <QLoggingCategory>  // Для логирования

FindAggressorAction::FindAggressorAction()
{
    // Конструктор пуст, вся логика в методе tick()
}

NodeStatus FindAggressorAction::tick(BTContext& context)
{
    // --- Шаг 1: Получаем наш собственный GUID ---
    const uint64_t myGuid = context.character->getGuid();
    if (myGuid == 0)
    {
        qCWarning(logBT) << "FindAggressorAction: Cannot find my own GUID.";
        return NodeStatus::Failure;  // Не можем найти себя, поиск невозможен
    }

    // --- Шаг 2: Получаем список всех видимых юнитов ---
    const auto visibleUnits = context.gameObjectManager->getObjectsByType(GameObjectType::Unit);

    // --- Шаг 3: Ищем в списке "нашего" агрессора ---
    for (const GameObjectInfo* unit : visibleUnits)
    {
        // Пропускаем себя и мертвых юнитов
        if (unit->guid == myGuid || unit->Health == 0)
        {
            continue;
        }

        // Главная проверка: получаем цель этого юнита
        const uint64_t unitTargetGuid = unit->targetGuid;  // Мы добавили это поле в GameObjectInfo

        // Сравниваем цель юнита с нашим GUID
        if (unitTargetGuid == myGuid)
        {
            // НАШЛИ!
            qCDebug(logBT) << "Aggressor found! GUID:" << Qt::hex << unit->guid;

            // Записываем GUID агрессора в контекст, чтобы другие узлы могли его использовать
            context.currentTargetGuid = unit->guid;

            // Задача успешно выполнена
            return NodeStatus::Success;
        }
    }

    // --- Шаг 4: Если мы прошли весь цикл и никого не нашли ---
    qCDebug(logBT) << "No unit is currently targeting us.";
    return NodeStatus::Failure;  // Агрессор не найден
}