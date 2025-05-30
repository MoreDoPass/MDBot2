#include "CharacterWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>

Q_LOGGING_CATEGORY(logCharacterWidget, "mdbot.gui.characterwidget")

CharacterWidget::CharacterWidget(Character* character, QWidget* parent) : QWidget(parent), m_character(character)
{
    try
    {
        auto* mainLayout = new QVBoxLayout(this);
        m_nameLabel = new QLabel(tr("Имя: -"), this);
        m_levelLabel = new QLabel(tr("Уровень: -"), this);
        m_healthLabel = new QLabel(tr("HP: - / -"), this);
        m_manaLabel = new QLabel(tr("Мана: - / -"), this);
        m_positionLabel = new QLabel(tr("Позиция: -"), this);
        m_stateLabel = new QLabel(tr("Состояние: -"), this);
        m_updateButton = new QPushButton(tr("Обновить"), this);
        m_autoUpdateCheck = new QCheckBox(tr("Автообновление"), this);
        m_autoUpdateTimer = new QTimer(this);
        m_autoUpdateTimer->setInterval(1000);
        m_autoUpdateTimer->setSingleShot(false);

        mainLayout->addWidget(m_nameLabel);
        mainLayout->addWidget(m_levelLabel);
        mainLayout->addWidget(m_healthLabel);
        mainLayout->addWidget(m_manaLabel);
        mainLayout->addWidget(m_positionLabel);
        mainLayout->addWidget(m_stateLabel);
        auto* hLayout = new QHBoxLayout();
        hLayout->addWidget(m_updateButton);
        hLayout->addWidget(m_autoUpdateCheck);
        mainLayout->addLayout(hLayout);
        setLayout(mainLayout);

        connect(m_updateButton, &QPushButton::clicked, this, &CharacterWidget::onUpdateClicked);
        connect(m_autoUpdateCheck, &QCheckBox::toggled, m_autoUpdateTimer,
                [this](bool checked)
                {
                    if (checked)
                        m_autoUpdateTimer->start();
                    else
                        m_autoUpdateTimer->stop();
                });
        connect(m_autoUpdateTimer, &QTimer::timeout, this, &CharacterWidget::onAutoUpdateTimeout);
        if (m_character)
        {
            connect(m_character, &Character::dataChanged, this, &CharacterWidget::onCharacterDataChanged);
            updateUi(m_character->data());
        }
        else
        {
            logError(tr("Character не инициализирован!"));
        }
    }
    catch (const std::exception& ex)
    {
        logError(tr("Ошибка при создании CharacterWidget: %1").arg(ex.what()));
    }
    catch (...)
    {
        logError(tr("Неизвестная ошибка при создании CharacterWidget"));
    }
}

CharacterWidget::~CharacterWidget() = default;

void CharacterWidget::onUpdateClicked()
{
    if (!m_character)
    {
        logError(tr("Character не инициализирован!"));
        return;
    }
    if (!m_character->updateFromMemory())
    {
        logError(tr("Ошибка обновления данных персонажа!"));
    }
}

void CharacterWidget::onAutoUpdateTimeout()
{
    if (m_character)
    {
        if (!m_character->updateFromMemory())
        {
            logError(tr("Ошибка автообновления данных персонажа!"));
        }
    }
}

void CharacterWidget::onCharacterDataChanged(const CharacterData& data)
{
    updateUi(data);
}

void CharacterWidget::updateUi(const CharacterData& data)
{
    m_nameLabel->setText(tr("Имя: %1").arg(data.name));
    m_levelLabel->setText(tr("Уровень: %1").arg(data.level));
    m_healthLabel->setText(tr("HP: %1 / %2").arg(data.health).arg(data.maxHealth));
    m_manaLabel->setText(tr("Мана: %1 / %2").arg(data.mana).arg(data.maxMana));
    m_positionLabel->setText(
        tr("Позиция: X=%1 Y=%2 Z=%3").arg(data.posX, 0, 'f', 2).arg(data.posY, 0, 'f', 2).arg(data.posZ, 0, 'f', 2));
    m_stateLabel->setText(tr("Состояние: %1").arg(data.inCombat ? "В бою" : "Мирно"));
}

void CharacterWidget::logError(const QString& message)
{
    qCCritical(logCharacterWidget) << message;
    QMessageBox::critical(this, tr("Ошибка"), message);
}
