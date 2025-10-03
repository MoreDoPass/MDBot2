#pragma once

#include "DecoratorNode.h"
#include <functional>

// Объявляем QLoggingCategory для логирования, если вы планируете его использовать.
// Если нет, эту строку можно убрать.
Q_DECLARE_LOGGING_CATEGORY(logBehaviorTree)

/**
 * @class RunWhileConditionDecorator
 * @brief Декоратор, который выполняет своего дочернего узла, пока внешнее условие истинно.
 * @details
 * Этот узел-декоратор является ключевым для создания "состояний" в дереве поведения.
 * В каждом тике он сначала проверяет заданное в конструкторе условие (лямбда-функцию).
 *
 * 1. Если условие возвращает `false`, декоратор немедленно возвращает `Failure`, не запуская дочерний узел.
 *    Это позволяет дереву "выйти" из текущего состояния и попробовать другие ветки.
 *
 * 2. Если условие возвращает `true`, декоратор запускает своего дочернего узла ("ребенка").
 *    - Если ребенок возвращает `Running`, декоратор просто пробрасывает этот статус дальше.
 *    - Если ребенок возвращает `Success` или `Failure`, декоратор ПЕРЕОПРЕДЕЛЯЕТ этот результат
 *      и возвращает `Running`. Это "захватывает" выполнение и не дает дереву по ошибке
 *      переключиться на другие ветки, пока основное условие (например, "в бою") все еще активно.
 *
 * @see WhileSuccessDecorator - в отличие от него, этот узел проверяет внешнее условие,
 *      а не результат работы дочернего узла.
 */
class RunWhileConditionDecorator : public DecoratorNode
{
   public:
    /**
     * @brief Псевдоним для функции-условия для удобства.
     * @param BTContext& Контекст дерева для выполнения проверки.
     * @return bool `true`, если условие выполнено, иначе `false`.
     */
    using ConditionFunc = std::function<bool(BTContext&)>;

    /**
     * @brief Конструктор.
     * @param child Указатель на дочерний узел, который будет выполняться.
     * @param condition Функция (обычно лямбда), которая будет проверяться в каждом тике.
     */
    RunWhileConditionDecorator(std::unique_ptr<BTNode> child, ConditionFunc condition);

   protected:
    NodeStatus tick(BTContext& context) override;

   private:
    /// @brief Функция-условие для проверки.
    ConditionFunc m_condition;
};