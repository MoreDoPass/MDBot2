#pragma once
#include "core/BehaviorTree/BTNode.h"
#include <vector>
#include <set>

/**
 * @brief "Навык", который ищет ближайший игровой объект из заданного списка ID.
 * @details Это универсальный искатель. Ему можно "скормить" любой список ID
 *          (руда, трава, квестовые предметы), и он найдет ближайший.
 *          При поиске он игнорирует объекты, находящиеся как в глобальном
 *          постоянном черном списке, так и во временном черном списке бота.
 */
class FindObjectByIdAction : public BTNode
{
   public:
    /**
     * @brief Конструктор.
     * @param idsToFind Вектор с Entry ID объектов, которые нужно искать.
     */
    explicit FindObjectByIdAction(std::vector<int> idsToFind);
    NodeStatus tick(BTContext& context) override;

   private:
    /// @brief Множество ID для быстрого поиска (O(log n) вместо O(n)).
    std::set<int> m_idsToFind;
};