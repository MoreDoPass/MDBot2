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
class CharacterWidget;
class DebugWidget;

Q_DECLARE_LOGGING_CATEGORY(logBotWidget)

class BotWidget : public QWidget
{
    Q_OBJECT
   public:
    explicit BotWidget(Bot* bot, ProfileManager* profileManager, QWidget* parent = nullptr);
    ~BotWidget();

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
    CharacterWidget* m_characterWidget = nullptr;
    DebugWidget* m_debugWidget = nullptr;
    QTabWidget* m_tabWidget = nullptr;
};