#pragma once
#include "core/BehaviorTree/BTNode.h"
#include "core/Bot/Settings/BotSettings.h"  // Подключаем настройки
#include <memory>

class OreGrindModule
{
   public:
    /**
     * @brief Собирает дерево поведения для модуля сбора ресурсов.
     * @param settings Полный набор настроек бота.
     * @return Указатель на корень собранного дерева.
     */
    static std::unique_ptr<BTNode> build(const BotStartSettings& settings);
};