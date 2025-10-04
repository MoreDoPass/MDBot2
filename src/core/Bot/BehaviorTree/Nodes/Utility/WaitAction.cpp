// --- START OF FILE WaitAction.cpp ---

#include "WaitAction.h"
#include "core/BehaviorTree/BTContext.h"  // Добавим для полноты

WaitAction::WaitAction(float milliseconds) : m_waitTimeMs(milliseconds) {}

// ИЗМЕНЕНИЕ: Имя функции теперь 'tick', как и в .h файле
NodeStatus WaitAction::tick(BTContext& context)
{
    // Если мы еще не начали ждать, это первый вызов.
    // Засекаем время и сообщаем дереву, что мы "в процессе выполнения".
    if (!m_isWaiting)
    {
        m_startTime = std::chrono::steady_clock::now();
        m_isWaiting = true;
        return NodeStatus::Running;
    }

    // Если мы уже ждем, проверяем, сколько времени прошло.
    auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_startTime);

    // Если прошло достаточно времени...
    if (elapsed.count() >= m_waitTimeMs)
    {
        m_isWaiting = false;         // Сбрасываем флаг, чтобы узел мог быть использован снова.
        return NodeStatus::Success;  // ...сообщаем, что действие успешно завершено.
    }

    // Если время еще не вышло, продолжаем ждать.
    // Снова возвращаем Running, чтобы дерево вызвало нас на следующем тике.
    return NodeStatus::Running;
}