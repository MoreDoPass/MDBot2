#include "MainWidget.h"
#include "core/Bot/Bot.h"
#include "core/BlacklistManager/BlacklistManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>

Q_LOGGING_CATEGORY(logMainWidget, "mdbot.gui.mainwidget")

MainWidget::MainWidget(Bot* bot, QWidget* parent) : QWidget(parent), m_bot(bot)
{
    auto* mainLayout = new QVBoxLayout(this);
    m_statusLabel = new QLabel(tr("Статус: Остановлен"), this);
    m_startButton = new QPushButton(tr("Старт"), this);
    m_stopButton = new QPushButton(tr("Стоп"), this);
    m_blacklistButton = new QPushButton(tr("В ЧС тек. цель"), this);
    m_stopButton->setEnabled(false);

    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(m_startButton);
    buttonLayout->addWidget(m_stopButton);
    buttonLayout->addWidget(m_blacklistButton);

    m_moduleComboBox = new QComboBox(this);
    m_moduleComboBox->addItem(tr("Сбор ресурсов"), QVariant::fromValue(ModuleType::Gathering));
    m_moduleComboBox->addItem(tr("Гринд мобов"), QVariant::fromValue(ModuleType::Grinding));
    m_moduleComboBox->addItem(tr("Выполнение квестов (в разработке)"), QVariant::fromValue(ModuleType::Questing));
    m_moduleComboBox->setItemData(2, false, Qt::ItemIsEnabled);

    mainLayout->addWidget(m_statusLabel);
    mainLayout->addLayout(buttonLayout);
    mainLayout->addWidget(new QLabel(tr("Активный модуль:")));
    mainLayout->addWidget(m_moduleComboBox);
    mainLayout->addStretch();
    setLayout(mainLayout);

    connect(m_startButton, &QPushButton::clicked, this, &MainWidget::onStartClicked);
    connect(m_stopButton, &QPushButton::clicked, this, &MainWidget::onStopClicked);
    connect(m_blacklistButton, &QPushButton::clicked, this, &MainWidget::onBlacklistCurrentTargetClicked);

    if (m_bot)
    {
        connect(m_bot, &Bot::finished, this, &MainWidget::onBotFinished);
    }
}

MainWidget::~MainWidget() = default;

void MainWidget::onStartClicked()
{
    if (m_bot)
    {
        m_startButton->setEnabled(false);
        m_stopButton->setEnabled(true);
        m_moduleComboBox->setEnabled(false);
        updateStatus(tr("Работает"));
        ModuleType selectedModule = m_moduleComboBox->currentData().value<ModuleType>();
        emit startRequested(selectedModule);
    }
}

void MainWidget::onStopClicked()
{
    if (m_bot)
    {
        emit stopRequested();
    }
}

void MainWidget::onBotFinished()
{
    m_startButton->setEnabled(true);
    m_stopButton->setEnabled(false);
    m_moduleComboBox->setEnabled(true);
    updateStatus(tr("Остановлен"));
}

void MainWidget::updateStatus(const QString& status, bool error)
{
    m_statusLabel->setText(tr("Статус: %1").arg(status));
    if (error)
        m_statusLabel->setStyleSheet("color: red;");
    else
        m_statusLabel->setStyleSheet("");
}

void MainWidget::onBlacklistCurrentTargetClicked()
{
    if (!m_bot)
    {
        qCWarning(logMainWidget) << "Blacklist button clicked, but bot object is null.";
        return;
    }
    const quint64 guid = m_bot->getCurrentTargetGuid();
    if (guid != 0)
    {
        // Простой, прямой, неблокирующий вызов.
        BlacklistManager::instance().add(guid);
        qCInfo(logMainWidget) << "User blacklisted target with GUID:" << Qt::hex << guid;
    }
    else
    {
        qCWarning(logMainWidget) << "Blacklist button clicked, but bot has no current target.";
    }
}