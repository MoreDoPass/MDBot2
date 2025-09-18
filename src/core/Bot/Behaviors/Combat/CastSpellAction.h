#pragma once

#include "core/BehaviorTree/BTNode.h"
#include "core/Bot/Behaviors/Shared/UnitSource.h"  // <-- Используем наш общий, правильный enum

/**
 * @class CastSpellAction
 * @brief Универсальный узел для использования заклинания на указанную цель
 *        (себя или текущую цель в контексте).
 */
class CastSpellAction : public BTNode
{
   public:
    /**
     * @brief Конструктор.
     * @param target Инструкция, указывающая, на кого будет использовано заклинание.
     * @param spellId ID заклинания для использования.
     */
    CastSpellAction(UnitSource target, int spellId);

    NodeStatus tick(BTContext& context) override;

   private:
    UnitSource m_target;
    int m_spellId;
};