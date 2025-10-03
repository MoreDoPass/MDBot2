#pragma once
#include <memory>

class BTNode;
class BTContext;

/**
 * @class CombatBuilder
 * @brief Фабрика, отвечающая ИСКЛЮЧИТЕЛЬНО за сборку боевой логики.
 */
class CombatBuilder
{
   public:
    /**
     * @brief Собирает и возвращает дерево боевого поведения для текущего спека.
     * @param context Контекст, из которого будет взята настройка `context->settings.spec`.
     * @return Указатель на корень готового дерева боевой логики.
     */
    static std::unique_ptr<BTNode> buildCombatLogic(BTContext& context);
};