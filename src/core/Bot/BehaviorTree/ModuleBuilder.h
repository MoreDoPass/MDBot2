#pragma once
#include <memory>

class BTNode;
class BTContext;

/**
 * @class ModuleBuilder
 * @brief Фабрика, отвечающая за сборку основного дерева поведения (модуля).
 * @details Этот класс смотрит на настройки в контексте (context.settings.activeModule)
 *          и на их основе строит соответствующее дерево поведения (гринд, сбор и т.д.),
 *          встраивая в него уже готовую боевую логику.
 */
class ModuleBuilder
{
   public:
    /**
     * @brief Собирает и возвращает дерево поведения для выбранного модуля.
     * @param context Контекст, из которого будут взяты настройки.
     * @param combatBehavior Готовое дерево боевой логики, которое будет передано
     *                       внутрь строящегося модуля для использования.
     * @return Указатель на корень готового дерева модуля.
     */
    static std::unique_ptr<BTNode> build(BTContext& context, std::unique_ptr<BTNode> combatBehavior);
};