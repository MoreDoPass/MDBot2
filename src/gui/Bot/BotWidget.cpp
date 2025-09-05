#include "BotWidget.h"
#include "core/Bot/Bot.h"
#include "gui/Bot/Modules/Character/CharacterWidget.h"
#include "gui/Bot/Modules/Main/MainWidget.h"
#include "gui/Bot/Modules/Debug/DebugWidget.h"
#include "gui/Bot/Modules/Gathering/GatheringWidget.h"
#include "gui/Bot/Modules/Settings/SettingsWidget.h"

#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTabWidget>

Q_LOGGING_CATEGORY(logBotWidget, "mdbot.gui.botwidget")

BotWidget::BotWidget(Bot* bot, QWidget* parent) : QWidget(parent), m_bot(bot)
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

            m_settingsWidget = new SettingsWidget(this);
            m_tabWidget->addTab(m_settingsWidget, tr("Настройки"));

            m_gatheringWidget = new GatheringWidget(this);
            m_tabWidget->addTab(m_gatheringWidget, tr("Сбор ресурсов"));

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
    if (!m_bot) return;

    qCInfo(logBotWidget) << "Start requested. Gathering settings for module type:" << static_cast<int>(type);

    // 1. Создаем пустую структуру для настроек
    BotStartSettings settings;

    // 2. Заполняем ее данными из всех виджетов
    settings.activeModule = type;  // Тип модуля мы получили из сигнала

    if (m_settingsWidget)
    {
        settings.globalSettings = m_settingsWidget->getSettings();
    }
    if (m_gatheringWidget)
    {
        settings.gatheringSettings = m_gatheringWidget->getSettings();
    }
    // Здесь можно будет добавить получение настроек из других виджетов (GrindingWidget и т.д.)

    // 3. Отправляем боту одну, полностью собранную структуру
    m_bot->start(settings);
}
