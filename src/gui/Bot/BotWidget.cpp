#include "BotWidget.h"
#include "core/Bot/Bot.h"
#include "core/ProfileManager/ProfileManager.h"
#include "gui/Bot/Modules/Character/CharacterWidget.h"
#include "gui/Bot/Modules/Main/MainWidget.h"
#include "gui/Bot/Modules/Debug/DebugWidget.h"
#include "gui/Bot/Modules/Gathering/GatheringWidget.h"
#include "gui/Bot/Modules/Grinding/GrindingWidget.h"
#include "gui/Bot/Modules/Settings/SettingsWidget.h"
#include "gui/Bot/Modules/Combat/CombatWidget.h"

#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTabWidget>

Q_LOGGING_CATEGORY(logBotWidget, "mdbot.gui.botwidget")

BotWidget::BotWidget(Bot* bot, ProfileManager* profileManager, QWidget* parent)  // <-- ИЗМЕНЕНО
    : QWidget(parent), m_bot(bot), m_profileManager(profileManager)              // <-- ИЗМЕНЕНО
{
    try
    {
        qCInfo(logBotWidget) << "Создан BotWidget для PID:" << (m_bot ? m_bot->processId() : -1);
        auto* layout = new QVBoxLayout(this);
        if (m_bot)
        {
            auto* pidLabel = new QLabel(tr("PID процесса: %1").arg(m_bot->processId()), this);
            layout->addWidget(pidLabel);
            m_tabWidget = new QTabWidget(this);

            m_mainWidget = new MainWidget(m_bot, this);
            m_tabWidget->addTab(m_mainWidget, tr("Главное"));

            m_combatWidget = new CombatWidget(this);
            m_tabWidget->addTab(m_combatWidget, tr("Бой"));

            m_settingsWidget = new SettingsWidget(this);
            m_tabWidget->addTab(m_settingsWidget, tr("Настройки"));

            m_gatheringWidget = new GatheringWidget(this);
            m_tabWidget->addTab(m_gatheringWidget, tr("Сбор ресурсов"));

            m_grindingWidget = new GrindingWidget(m_profileManager, this);  // <-- 2. Создаем экземпляр виджета
            m_tabWidget->addTab(m_grindingWidget, tr("Гринд мобов"));       // <-- 3. Добавляем его как вкладку

            if (m_bot->character())
            {
                m_characterWidget = new CharacterWidget(m_bot->character(), this);
                m_tabWidget->addTab(m_characterWidget, tr("Персонаж"));
            }
            else
            {
                m_tabWidget->addTab(new QLabel(tr("Ошибка: Character не инициализирован!"), this), tr("Персонаж"));
                qCCritical(logBotWidget) << "Character не инициализирован в BotWidget!";
            }

            m_debugWidget = new DebugWidget(m_bot, this);
            m_tabWidget->addTab(m_debugWidget, tr("Отладка"));

            layout->addWidget(m_tabWidget);

            // --- ГЛАВНЫЕ СОЕДИНЕНИЯ ---
            // MainWidget просит запустить -> BotWidget собирает все настройки и командует боту
            connect(m_mainWidget, &MainWidget::startRequested, this, &BotWidget::onStartRequested);
            // MainWidget просит остановить -> BotWidget напрямую командует боту
            connect(m_mainWidget, &MainWidget::stopRequested, m_bot, &Bot::stop);
            // Виджет отладки просит данные -> BotWidget напрямую просит бота их предоставить
            connect(m_debugWidget, &DebugWidget::refreshRequested, m_bot, &Bot::provideDebugData);
            // Бот предоставил данные -> BotWidget передает их виджету отладки
            connect(m_bot, &Bot::debugDataReady, m_debugWidget, &DebugWidget::onDebugDataReady);
        }
        else
        {
            layout->addWidget(new QLabel(tr("Ошибка: Bot не инициализирован!"), this));
            qCCritical(logBotWidget) << "Bot не инициализирован в BotWidget!";
        }
        setLayout(layout);
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBotWidget) << "Ошибка при создании BotWidget:" << ex.what();
    }
}

BotWidget::~BotWidget()
{
    qCInfo(logBotWidget) << "Уничтожение BotWidget";
}

void BotWidget::onStartRequested(ModuleType type)
{
    if (!m_bot)
    {
        qCCritical(logBotWidget) << "Start requested, but bot object is null!";
        return;
    }

    qCInfo(logBotWidget) << "Start requested. Gathering settings for module type:" << static_cast<int>(type);

    // 1. Создаем пустую структуру для настроек
    BotStartSettings settings;

    // 2. Заполняем ее данными из всех виджетов
    settings.activeModule = type;  // Тип модуля мы получили из сигнала

    if (m_settingsWidget)
    {
        settings.movementSettings = m_settingsWidget->getSettings();
    }
    else
    {
        qCWarning(logBotWidget) << "SettingsWidget is null, default movement settings will be used.";
    }

    // --- ЭТО ИСПРАВЛЕНИЕ ---
    // Проверяем, существует ли виджет настроек сбора, и если да, получаем из него настройки.
    if (m_gatheringWidget)
    {
        settings.gatheringSettings = m_gatheringWidget->getSettings();
        // Добавляем ключевой лог, чтобы проверить, что путь дошел до этого места.
        qCInfo(logBotWidget) << "Gathering settings collected. Profile path is:"
                             << settings.gatheringSettings.profilePath;
    }
    else
    {
        qCWarning(logBotWidget) << "GatheringWidget is null, default gathering settings will be used.";
    }

    if (m_grindingWidget)
    {
        settings.grindingSettings = m_grindingWidget->getSettings();
        qCInfo(logBotWidget) << "Grinding settings collected. NPC IDs count:"
                             << settings.grindingSettings.npcIdsToGrind.size();
    }

    if (m_combatWidget)
    {
        settings.spec = m_combatWidget->getSpec();
        qCInfo(logBotWidget) << "Combat spec collected:" << static_cast<int>(settings.spec);
    }
    else
    {
        qCWarning(logBotWidget) << "CombatWidget is null, default combat spec will be used.";
    }

    // Здесь можно будет добавить получение настроек из других виджетов (GrindingWidget и т.д.)

    // 3. Отправляем боту одну, полностью собранную структуру
    m_bot->start(settings, m_profileManager);
}
