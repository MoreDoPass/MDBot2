#include "RunWhileConditionDecorator.h"

// Если вы используете логирование, определите категорию.
#include <QLoggingCategory>
Q_LOGGING_CATEGORY(logBehaviorTree, "bt.decorator.runwhile")

RunWhileConditionDecorator::RunWhileConditionDecorator(std::unique_ptr<BTNode> child, ConditionFunc condition)
    : DecoratorNode(std::move(child)), m_condition(std::move(condition))
{
    if (!m_condition)
    {
        // Хорошая практика - проверять, что нам передали валидную функцию,
        // чтобы избежать падений в будущем.
        qCCritical(logBehaviorTree) << "RunWhileConditionDecorator was created with a null condition function!";
    }
}

NodeStatus RunWhileConditionDecorator::tick(BTContext& context)
{
    // 1. Проверяем наше внешнее условие.
    if (!m_condition || !m_condition(context))
    {
        // Если функция-условие не задана или вернула false, то состояние больше не активно.
        // Возвращаем Failure, чтобы родительский Selector мог перейти к следующей ветке.
        return NodeStatus::Failure;
    }

    // 2. Условие истинно, значит, мы находимся в нужном "состоянии". Запускаем дочерний узел.
    const NodeStatus childStatus = m_child->tick(context);

    // 3. Анализируем результат от "ребенка".
    if (childStatus == NodeStatus::Running)
    {
        // Если ребенок уже занят (например, кастует заклинание), то просто пробрасываем его статус.
        return NodeStatus::Running;
    }

    // 4. КЛЮЧЕВАЯ ЛОГИКА: Если ребенок закончил свою задачу на этот тик (Success или Failure),
    // мы НЕ выходим из нашего состояния. Мы возвращаем Running, потому что наше главное
    // условие (m_condition) все еще истинно. Это и есть тот самый "захват" управления,
    // который не дает боту дергаться между боем и сбором руды.
    return NodeStatus::Running;
}