// --- НАЧАЛО ФАЙЛА MobGrindModule.h ---
#pragma once

#include "core/BehaviorTree/BTNode.h"
#include "core/BehaviorTree/BTContext.h"
#include <memory>
#include <QLoggingCategory>

// Объявляем категорию логирования для этого модуля, чтобы можно было использовать ее в .cpp файле
Q_DECLARE_LOGGING_CATEGORY(lcMobGrindModule)

/**
 * @class MobGrindModule
 * @brief Статический класс-фабрика для создания дерева поведения,
 * отвечающего за гринд (убийство) мобов.
 *
 * Дерево строится по принципу приоритетов:
 * 1. Безопасность (убежать от игроков).
 * 2. Восстановление (еда/питье вне боя).
 * 3. Эффективность (сбор добычи с трупов).
 * 4. Основная деятельность (бой, поиск новых целей, движение по маршруту).
 */
class MobGrindModule
{
   public:
    /**
     * @brief Собирает и возвращает корень дерева поведения для модуля гринда мобов.
     * @param context Общий контекст, передаваемый всем узлам дерева.
     * @param combatBehavior Уже собранное дерево боевой логики, которое будет встроено в общую схему.
     * @return Указатель на корневой узел дерева поведения модуля.
     */
    static std::unique_ptr<BTNode> build(BTContext& context, std::unique_ptr<BTNode> combatBehavior);

   private:
    // --- ПРИВАТНЫЕ МЕТОДЫ-СБОРЩИКИ ДЛЯ КАЖДОЙ ВЕТКИ ЛОГИКИ ---

    /** @brief Создает ветку для панического бегства, если рядом вражеский игрок. */
    static std::unique_ptr<BTNode> createPanicBranch(BTContext& context);

    /** @brief Создает ветку для восстановления здоровья и маны вне боя. */
    static std::unique_ptr<BTNode> createRestBranch(BTContext& context);

    /** @brief Создает ветку для поиска и сбора добычи с убитых мобов. */
    static std::unique_ptr<BTNode> createLootBranch(BTContext& context);

    /** @brief Создает ветку полного цикла гринда: поиск цели и инициирование атаки. */
    static std::unique_ptr<BTNode> createFullGrindCycleBranch(BTContext& context);

    /** @brief Создает ветку для движения по заданному маршруту, если нет других задач. */
    static std::unique_ptr<BTNode> createFollowPathBranch(BTContext& context);

    /** @brief Создает основную рабочую ветку, объединяющую бой, поиск цели и движение. */
    static std::unique_ptr<BTNode> createWorkLogicBranch(BTContext& context, std::unique_ptr<BTNode> combatBehavior);
};
// --- КОНЕЦ ФАЙЛА MobGrindModule.h ---