#include "IsHealthCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include "shared/Structures/GameObject.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logHealthCondition, "mdbot.bt.condition.health")

IsHealthCondition::IsHealthCondition(UnitSource source, ComparisonType comparison, HealthCheckType checkType,
                                     float value)
    : m_source(source), m_comparison(comparison), m_checkType(checkType), m_value(value)
{
}

/**
 * @brief Вспомогательная функция для выполнения сравнения.
 * @param val1 Первое значение.
 * @param val2 Второе значение.
 * @param op Оператор сравнения.
 * @return true, если условие выполнено.
 */
static bool compareValues(float val1, float val2, ComparisonType op)
{
    switch (op)
    {
        case ComparisonType::Less:
            return val1 < val2;
        case ComparisonType::LessOrEqual:
            return val1 <= val2;
        case ComparisonType::Equal:
            return val1 == val2;  // Будьте осторожны с float-сравнениями
        case ComparisonType::GreaterOrEqual:
            return val1 >= val2;
        case ComparisonType::Greater:
            return val1 > val2;
        default:
            return false;
    }
}

NodeStatus IsHealthCondition::tick(BTContext& context)
{
    // --- ШАГ 1: ПОЛУЧАЕМ ДАННЫЕ О ЗДОРОВЬЕ ЮНИТА ---

    float currentHealth = 0;
    float maxHealth = 0;

    if (m_source == UnitSource::Self)
    {
        currentHealth = static_cast<float>(context.character->getHealth());
        maxHealth = static_cast<float>(context.character->getMaxHealth());
    }
    else  // m_source == UnitSource::CurrentTarget
    {
        if (context.currentTargetGuid == 0)
        {
            return NodeStatus::Failure;  // Нет цели - нет здоровья для проверки
        }

        const GameObjectInfo* targetInfo = context.gameObjectManager->getObjectByGuid(context.currentTargetGuid);
        if (!targetInfo)
        {
            return NodeStatus::Failure;  // Цель исчезла
        }
        currentHealth = static_cast<float>(targetInfo->Health);
        maxHealth = static_cast<float>(targetInfo->maxHealth);
    }

    // --- ШАГ 2: ВЫЧИСЛЯЕМ ЗНАЧЕНИЕ ДЛЯ ПРОВЕРКИ ---

    float valueToCompare = 0.0f;
    switch (m_checkType)
    {
        case HealthCheckType::Percentage:
            // Защита от деления на ноль, если у юнита по какой-то причине 0 макс. здоровья
            valueToCompare = (maxHealth > 0) ? (currentHealth / maxHealth) * 100.0f : 0.0f;
            break;
        case HealthCheckType::Absolute:
            valueToCompare = currentHealth;
            break;
        case HealthCheckType::Missing:
            valueToCompare = maxHealth - currentHealth;
            break;
    }

    // --- ШАГ 3: СРАВНИВАЕМ И ВОЗВРАЩАЕМ РЕЗУЛЬТАТ ---

    if (compareValues(valueToCompare, m_value, m_comparison))
    {
        qCDebug(logHealthCondition) << "Condition SUCCESS: Source" << (m_source == UnitSource::Self ? "Self" : "Target")
                                    << "value (" << valueToCompare << ") satisfied comparison with (" << m_value << ")";
        return NodeStatus::Success;
    }

    qCDebug(logHealthCondition) << "Condition FAILURE: Source" << (m_source == UnitSource::Self ? "Self" : "Target")
                                << "value (" << valueToCompare << ") did not satisfy comparison with (" << m_value
                                << ")";
    return NodeStatus::Failure;
}