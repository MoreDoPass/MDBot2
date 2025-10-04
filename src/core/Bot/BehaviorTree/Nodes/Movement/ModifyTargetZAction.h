// ФАЙЛ: src/core/Bot/BehaviorTree/Nodes/Movement/ModifyTargetZAction.h

#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class ModifyTargetZAction
 * @brief Модифицирует Z-координату цели в BTContext.
 * @details Этот узел берет `context.currentTargetPosition` и изменяет
 *          его Z-координату на заданное смещение. Это полезно, например,
 *          чтобы заставить бота лететь под землей.
 */
class ModifyTargetZAction : public BTNode
{
   public:
    /**
     * @brief Конструктор.
     * @param zOffset Смещение, которое будет добавлено к Z-координате (может быть отрицательным, например -100.0f).
     */
    explicit ModifyTargetZAction(float zOffset);

    /**
     * @brief Выполняет основную логику узла.
     * @param context Общий контекст дерева поведения.
     * @return Success, если координата была изменена, иначе Failure.
     */
    NodeStatus tick(BTContext& context) override;

   private:
    /// @brief Смещение по оси Z, которое будет применено к цели.
    float m_zOffset;
};