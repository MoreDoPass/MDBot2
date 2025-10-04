#pragma once
#include <memory>

class BTNode;
class BTContext;

/**
 * @class SystemBuilder
 * @brief Фабрика, отвечающая за сборку высокоприоритетных системных веток поведения.
 * @details Сюда входит логика, которая должна выполняться всегда, вне зависимости
 *          от основного модуля: проверки на смерть, дисконнект, угрозу от игроков и т.д.
 */
class SystemBuilder
{
   public:
    /**
     * @brief Собирает и возвращает дерево системных проверок.
     * @param context Контекст, необходимый для работы узлов.
     * @return Указатель на корень дерева системных проверок.
     */
    static std::unique_ptr<BTNode> build(BTContext& context);
};