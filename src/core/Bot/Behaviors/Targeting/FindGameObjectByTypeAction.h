#pragma once
#include "core/BehaviorTree/BTNode.h"
#include "shared/Structures/GameObject.h"  // Нам нужен GameObjectType

/**
 * @brief "Навык", который ищет ближайший игровой объект по заданному GameObjectType.
 */
class FindGameObjectByTypeAction : public BTNode
{
   public:
    explicit FindGameObjectByTypeAction(GameObjectType typeToFind);
    NodeStatus tick(BTContext& context) override;

   private:
    GameObjectType m_typeToFind;
};