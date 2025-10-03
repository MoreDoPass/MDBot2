// --- НАЧАЛО ФАЙЛА core/Bot/Behaviors/Profiles/LoadGrindingProfileAction.h ---
#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class LoadGrindingProfileAction
 * @brief "Навык", который загружает профиль для гринда мобов.
 * @details Этот узел должен быть первым в цепочке логики гринда. Он использует
 *          ProfileManager для загрузки и парсинга JSON-файла, путь к которому
 *          указан в настройках, и сохраняет результат в BTContext.
 */
class LoadGrindingProfileAction : public BTNode
{
   public:
    /**
     * @brief Основная логика узла. Выполняется на каждом тике дерева.
     * @param context Общий контекст дерева поведения.
     * @return Success, если профиль успешно загружен (или уже был загружен). Failure в случае ошибки.
     */
    NodeStatus tick(BTContext& context) override;
};