#include "HasRunesCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logHasRunes, "mdbot.bt.dk.hasrunes")

/**
 * @brief Вспомогательная функция для выполнения сравнения целочисленных значений.
 * @param val1 Текущее значение.
 * @param val2 Требуемое значение.
 * @param op Оператор сравнения.
 * @return true, если условие выполнено.
 */
static bool compareValues(int val1, int val2, ComparisonType op)
{
    switch (op)
    {
        case ComparisonType::Less:
            return val1 < val2;
        case ComparisonType::LessOrEqual:
            return val1 <= val2;
        case ComparisonType::Equal:
            return val1 == val2;
        case ComparisonType::GreaterOrEqual:
            return val1 >= val2;
        case ComparisonType::Greater:
            return val1 > val2;
        default:
            return false;
    }
}

HasRunesCondition::HasRunesCondition(RuneType type, int amount, ComparisonType comparison)
    : m_type(type), m_amount(amount), m_comparison(comparison)
{
}

NodeStatus HasRunesCondition::tick(BTContext& context)
{
    // 1. Получаем количество готовых рун нужного типа, используя наш метод из Character.
    const int currentRuneCount = context.character->getRuneCount(m_type);

    // 2. Сравниваем текущее количество с требуемым.
    if (compareValues(currentRuneCount, m_amount, m_comparison))
    {
        // Условие выполнено, ресурсов достаточно.
        qCDebug(logHasRunes) << "Condition SUCCESS: Have" << currentRuneCount << "ready" << (int)m_type
                             << "runes, needed" << m_amount;
        return NodeStatus::Success;
    }
    else
    {
        // Условие не выполнено, ресурсов не хватает.
        qCDebug(logHasRunes) << "Condition FAILURE: Have" << currentRuneCount << "ready" << (int)m_type
                             << "runes, needed" << m_amount;
        return NodeStatus::Failure;
    }
}