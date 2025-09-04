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
 * @brief Определяет, какой тип передвижения будет использовать бот.
 */
enum class MovementType
{
    Teleport,     ///< Использовать телепорт (мгновенное перемещение)
    GroundMount,  ///< Использовать наземного маунта
    FlyingMount   ///< Использовать летающего маунта
};

/**
 * @brief Глобальные настройки, применимые ко всем модулям.
 */
struct GlobalSettings
{
    MovementType movementType = MovementType::Teleport;  ///< Тип передвижения
};

/**
 * @brief Полная структура настроек, передаваемая боту при запуске.
 * @details Содержит всю информацию, необходимую для старта любого модуля.
 */
struct BotStartSettings
{
    ModuleType activeModule = ModuleType::None;  ///< Какой модуль запустить
    GlobalSettings globalSettings;               ///< Глобальные настройки
    GatheringSettings gatheringSettings;         ///< Настройки для модуля сбора (если он активен)
    // В будущем сюда можно добавить GrindingSettings, QuestingSettings и т.д.
};

// Регистрируем наш главный тип в системе Qt.
// Это единственное, что нужно, чтобы его можно было безопасно
// передавать через сигналы и слоты. Никаких Q_ENUM не нужно.
Q_DECLARE_METATYPE(BotStartSettings)