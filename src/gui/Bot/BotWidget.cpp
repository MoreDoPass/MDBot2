#include "BotWidget.h"
#include "core/Bot/Bot.h"
#include "gui/Bot/CharacterWidget/CharacterWidget.h"
#include "gui/Bot/MainWidget/MainWidget.h"
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
            // Вкладка "Главное"
            m_mainWidget = new MainWidget(m_bot, this);
            m_tabWidget->addTab(m_mainWidget, tr("Главное"));
            // Вкладка "Character"
            if (m_bot->character())
            {
                m_characterWidget = new CharacterWidget(m_bot->character(), m_bot->movementManager(), this);
                m_tabWidget->addTab(m_characterWidget, tr("Character"));
            }
            else
            {
                auto* errorLabel = new QLabel(tr("Ошибка: Character не инициализирован!"), this);
                m_tabWidget->addTab(errorLabel, tr("Character"));
                qCCritical(logBotWidget) << "Character не инициализирован в BotWidget!";
            }
            layout->addWidget(m_tabWidget);
            // Связь MainWidget с Bot (старт/стоп)
            connect(m_mainWidget, &MainWidget::startRequested,
                    [this]()
                    {
                        if (m_bot) m_bot->run();
                    });
            connect(m_mainWidget, &MainWidget::stopRequested,
                    [this]()
                    {
                        // Реализовать остановку бота через слот/флаг
                        // Например: m_bot->stop();
                    });
        }
        else
        {
            auto* errorLabel = new QLabel(tr("Ошибка: Bot не инициализирован!"), this);
            layout->addWidget(errorLabel);
            qCCritical(logBotWidget) << "Bot не инициализирован в BotWidget!";
        }
        setLayout(layout);
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBotWidget) << "Ошибка при создании BotWidget:" << ex.what();
    }
    catch (...)
    {
        qCCritical(logBotWidget) << "Неизвестная ошибка при создании BotWidget";
    }
}

BotWidget::~BotWidget()
{
    try
    {
        qCInfo(logBotWidget) << "Уничтожение BotWidget";
    }
    catch (const std::exception& ex)
    {
        qCCritical(logBotWidget) << "Ошибка при уничтожении BotWidget:" << ex.what();
    }
    catch (...)
    {
        qCCritical(logBotWidget) << "Неизвестная ошибка при уничтожении BotWidget";
    }
}