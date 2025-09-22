// Файл: core/Bot/Behaviors/Combat/IsSpellOnCooldownCondition.h
#pragma once

#include "core/BehaviorTree/ConditionNode.h"

/**
 * @class IsSpellOnCooldownCondition
 * @brief Узел-условие, который проверяет, находится ли заклинание на кулдауне.
 * @details Название обманчиво простое. Этот узел выполняет ДВЕ ключевые проверки:
 *          1. Не активен ли в данный момент Глобальный Кулдаун (ГКД)?
 *          2. Не находится ли само заклинание (по его ID) на своем личном кулдауне?
 *          Узел возвращает Success, только если ОБА условия выполнены (т.е. кулдауны готовы).
 */
class IsSpellOnCooldownCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param spellId ID заклинания для проверки. Также работает для заклинаний от предметов.
     */
    explicit IsSpellOnCooldownCondition(int spellId);

    NodeStatus tick(BTContext& context) override;

   private:
    int m_spellId;
};