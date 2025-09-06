// ФАЙЛ: src/core/Bot/Settings/BotSettings.h

#pragma once
#include "GatheringSettings.h"
#include <QVariant>

/**
 * @brief Определяет тип активного модуля (режима) работы бота.
 * @details Это обычный C++ enum, не привязанный к мета-объектной системе Qt.
 */
enum class ModuleType
{
    None,       ///< Нет активного модуля
    Gathering,  ///< Сбор ресурсов
    Grinding,   ///< Гринд мобов
    Questing    ///< Выполнение квестов
};

/**
 * @brief Настройки, связанные с передвижением бота.
 * @details Эта структура определяет, КАК и ЧЕМ бот будет передвигаться.
 */
struct MovementSettings
{
    /**
     * @brief Определяет стратегию (правила) навигации бота.
     * @details Этот enum напрямую управляет логикой выбора действий в Дереве Поведения.
     */
    enum class NavigationType
    {
        /** @brief Только Click-To-Move. Бот будет использовать обычный бег/маунта. Самый безопасный режим. */
        CtM_Only,

        /** @brief Гибридный режим. Бот будет пытаться телепортироваться, если рядом нет игроков. Если есть - будет
           использовать CtM. */
        CtM_And_Teleport,

        /** @brief Только Телепорт. Бот будет использовать исключительно телепорт для передвижения. Самый быстрый и
           рискованный режим. */
        Teleport_Only
    };

    /// @brief Какую стратегию навигации использовать. Выбирается в GUI.
    NavigationType navigationType = NavigationType::CtM_Only;

    // --- Дополнительные флаги, которые можно будет использовать в будущем ---
    bool useGroundMount = true;          ///< Разрешено ли использовать наземного маунта в режиме CtM.
    bool useFlyingMount = false;         ///< Разрешено ли использовать летающего маунта.
    float playerSafetyDistance = 40.0f;  ///< Дистанция, на которой другие игроки считаются "опасными" для телепорта.
};

/**
 * @brief Полная структура настроек, передаваемая боту при запуске.
 * @details Содержит всю информацию, необходимую для старта любого модуля.
 */
struct BotStartSettings
{
    ModuleType activeModule = ModuleType::None;  ///< Какой модуль запустить
    MovementSettings movementSettings;
    GatheringSettings gatheringSettings;  ///< Настройки для модуля сбора (если он активен)
    // В будущем сюда можно добавить GrindingSettings, QuestingSettings и т.д.
};

// Регистрируем наш главный тип в системе Qt.
// Это единственное, что нужно, чтобы его можно было безопасно
// передавать через сигналы и слоты. Никаких Q_ENUM не нужно.
Q_DECLARE_METATYPE(BotStartSettings)