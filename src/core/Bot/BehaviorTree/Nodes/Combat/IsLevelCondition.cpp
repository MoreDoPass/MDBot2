#include "IsLevelCondition.h"
#include "core/BehaviorTree/BTContext.h"  // Обязательно нужен для доступа к "кухонному столу"

IsLevelCondition::IsLevelCondition(UnitSource source, ComparisonType op, int level)
    : m_source(source), m_op(op), m_level(level)
{
    // Конструктор просто сохраняет инструкции, которые мы ему передали
}

NodeStatus IsLevelCondition::tick(BTContext& context)
{
    // --- Шаг 1: Получаем уровень юнита, следуя инструкции 'm_source' ---
    int unitLevel = -1;  // Начальное значение, означающее "уровень неизвестен"

    if (m_source == UnitSource::Self)
    {
        // Инструкция "Self": берем уровень нашего персонажа
        unitLevel = context.character->getLevel();
    }
    else  // m_source == UnitSource::CurrentTarget
    {
        // Инструкция "CurrentTarget": берем уровень текущей цели
        uint64_t targetGuid = context.currentTargetGuid;
        if (targetGuid != 0)
        {
            const GameObjectInfo* targetInfo = context.gameObjectManager->getObjectByGuid(targetGuid);
            if (targetInfo)
            {
                unitLevel = targetInfo->level;
            }
        }
    }

    // Если мы так и не смогли узнать уровень (например, цели нет), условие провалено
    if (unitLevel == -1)
    {
        return NodeStatus::Failure;
    }

    // --- Шаг 2: Выполняем сравнение, следуя инструкции 'm_op' ---
    bool conditionMet = false;
    switch (m_op)
    {
        case ComparisonType::GreaterOrEqual:
            conditionMet = (unitLevel >= m_level);
            break;
        case ComparisonType::Less:
            conditionMet = (unitLevel < m_level);
            break;
        case ComparisonType::Equal:
            conditionMet = (unitLevel == m_level);
            break;
    }

    // --- Шаг 3: Возвращаем результат ---
    return conditionMet ? NodeStatus::Success : NodeStatus::Failure;
}