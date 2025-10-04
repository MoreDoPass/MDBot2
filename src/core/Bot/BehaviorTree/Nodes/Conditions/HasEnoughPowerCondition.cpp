// --- НАЧАЛО ФАЙЛА HasEnoughPowerCondition.cpp ---
#include "HasEnoughPowerCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include "core/Bot/Character/Character.h"  // Нужен для доступа к context.character

/**
 * @brief Конструктор инициализирует поля класса значениями, переданными при создании узла.
 * @param type Тип ресурса (PowerType::Mana, PowerType::Rage и т.д.).
 * @param requiredAmount Количество ресурса, которое должно быть у персонажа.
 */
HasEnoughPowerCondition::HasEnoughPowerCondition(PowerType type, uint32_t requiredAmount)
    : m_powerType(type), m_requiredAmount(requiredAmount)
{
}

/**
 * @brief Основная логика узла. Вызывается каждый "тик" дерева.
 * @param context Контекст, содержащий всю информацию о состоянии бота, включая персонажа.
 * @return NodeStatus::Success, если ресурса достаточно, иначе NodeStatus::Failure.
 */
NodeStatus HasEnoughPowerCondition::tick(BTContext& context)  // ИЗМЕНЕНИЕ: Возвращаемый тип теперь NodeStatus
{
    // 1. Получаем доступ к нашему персонажу из контекста.
    const Character* character = context.character;
    if (!character)
    {
        return NodeStatus::Failure;  // Если персонажа нет, условие провалено.
    }

    // 2. Вызываем наш новый универсальный геттер, передавая ему нужный тип ресурса.
    const uint32_t currentPower = character->getCurrentPower(m_powerType);

    // 3. Сравниваем текущее значение с необходимым.
    if (currentPower >= m_requiredAmount)
    {
        return NodeStatus::Success;  // Успех! Ресурса достаточно.
    }
    else
    {
        return NodeStatus::Failure;  // Провал. Ресурса не хватает.
    }
}
// --- КОНЕЦ ФАЙЛА HasEnoughPowerCondition.cpp ---