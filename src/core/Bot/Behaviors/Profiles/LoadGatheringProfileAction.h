#pragma once
#include "core/BehaviorTree/BTNode.h"

/**
 * @class LoadGatheringProfileAction
 * @brief "Навык", который загружает профиль для сбора ресурсов.
 * @details Этот узел должен быть первым в цепочке логики сбора. Он использует
 *          ProfileManager для загрузки и парсинга JSON-файла, путь к которому
 *          указан в настройках, и сохраняет результат в BTContext.
 */
class LoadGatheringProfileAction : public BTNode
{
   public:
    NodeStatus tick(BTContext& context) override;
};