#pragma once
#include "core/BehaviorTree/ConditionNode.h"
#include "shared/Structures/Enums/GameObjectType.h"  // <-- Подключаем наш enum

/**
 * @class HasTargetCondition
 * @brief Узел-условие, который проверяет, выбрана ли у бота цель,
 *        и опционально - соответствует ли она заданному типу.
 */
class HasTargetCondition : public ConditionNode
{
   public:
    /**
     * @brief Конструктор.
     * @param requiredType (Опционально) Если указан тип (кроме None), узел проверит,
     *                     что текущая цель именно этого типа.
     */
    explicit HasTargetCondition(GameObjectType requiredType = GameObjectType::None);
    NodeStatus tick(BTContext& context) override;

   private:
    GameObjectType m_requiredType;
};