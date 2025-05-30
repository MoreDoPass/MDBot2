#include "MainWidget.h"
#include "core/Bot/Bot.h"
#include <QHBoxLayout>
#include <QVBoxLayout>

Q_LOGGING_CATEGORY(logMainWidget, "mdbot.gui.mainwidget")

MainWidget::MainWidget(Bot* bot, QWidget* parent) : QWidget(parent), m_bot(bot)
{
    auto* mainLayout = new QVBoxLayout(this);
    m_statusLabel = new QLabel(tr("Статус: Остановлен"), this);
    m_startButton = new QPushButton(tr("Старт"), this);
    m_stopButton = new QPushButton(tr("Стоп"), this);
    m_stopButton->setEnabled(false);

    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(m_startButton);
    buttonLayout->addWidget(m_stopButton);

    mainLayout->addWidget(m_statusLabel);
    mainLayout->addLayout(buttonLayout);
    setLayout(mainLayout);

    connect(m_startButton, &QPushButton::clicked, this, &MainWidget::onStartClicked);
    connect(m_stopButton, &QPushButton::clicked, this, &MainWidget::onStopClicked);
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
        updateStatus(tr("Работает"));
        emit startRequested();
    }
}

void MainWidget::onStopClicked()
{
    if (m_bot)
    {
        m_startButton->setEnabled(true);
        m_stopButton->setEnabled(false);
        updateStatus(tr("Остановлен"));
        emit stopRequested();
    }
}

void MainWidget::onBotFinished()
{
    m_startButton->setEnabled(true);
    m_stopButton->setEnabled(false);
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
