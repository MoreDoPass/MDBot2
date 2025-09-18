#include "HasBuffCondition.h"
#include "core/BehaviorTree/BTContext.h"  // Нужен для доступа к менеджерам

HasBuffCondition::HasBuffCondition(UnitSource target, int auraId, bool mustBePresent)
    : m_target(target), m_auraId(auraId), m_mustBePresent(mustBePresent)
{
    // Конструктор теперь просто инициализирует поля
}

NodeStatus HasBuffCondition::tick(BTContext& context)
{
    // Шаг 1: Определяем GUID юнита, которого нужно проверить.
    uint64_t guidToCheck = 0;
    if (m_target == UnitSource::Self)
    {
        guidToCheck = context.character->getGuid();
    }
    else  // m_target == BuffTarget::CurrentTarget
    {
        guidToCheck = context.currentTargetGuid;
    }

    // Если по какой-то причине мы не знаем, кого проверять, условие провалено.
    if (guidToCheck == 0)
    {
        return NodeStatus::Failure;
    }

    // Шаг 2: Используем наш GameObjectManager ("Глаза"), чтобы проверить наличие ауры.
    bool auraIsPresent = context.gameObjectManager->unitHasAura(guidToCheck, m_auraId);

    // Шаг 3: Сравниваем фактическое наличие ауры с тем, что нам было нужно.
    if (auraIsPresent == m_mustBePresent)
    {
        return NodeStatus::Success;  // Условие выполнено
    }

    return NodeStatus::Failure;  // Условие не выполнено
}