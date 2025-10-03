#pragma once

#include <QWidget>
#include <QLoggingCategory>
#include "core/Bot/Settings/BotSettings.h"  // Подключаем, чтобы знать ModuleType

// Прямые объявления для ускорения компиляции
class Bot;
class ProfileManager;
class QTabWidget;
class MainWidget;
class SettingsWidget;
class GatheringWidget;
class GrindingWidget;
class CharacterWidget;
class DebugWidget;
class CombatWidget;

Q_DECLARE_LOGGING_CATEGORY(logBotWidget)

class BotWidget : public QWidget
{
    Q_OBJECT
   public:
    explicit BotWidget(Bot* bot, ProfileManager* profileManager, QWidget* parent = nullptr);
    ~BotWidget();

    /**
     * @brief Возвращает указатель на объект Bot, которым управляет этот виджет.
     * @return Указатель на Bot.
     */
    Bot* bot() const
    {
        return m_bot;
    }

   private slots:
    /**
     * @brief Собирает настройки со всех дочерних виджетов и запускает бота.
     * @param type Тип модуля, который был выбран в MainWidget.
     */
    void onStartRequested(ModuleType type);

   private:
    Bot* m_bot;
    ProfileManager* m_profileManager = nullptr;
    MainWidget* m_mainWidget = nullptr;
    SettingsWidget* m_settingsWidget = nullptr;
    GatheringWidget* m_gatheringWidget = nullptr;
    GrindingWidget* m_grindingWidget = nullptr;
    CharacterWidget* m_characterWidget = nullptr;
    DebugWidget* m_debugWidget = nullptr;
    CombatWidget* m_combatWidget = nullptr;
    QTabWidget* m_tabWidget = nullptr;
};