#include "CharacterWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QGroupBox>

Q_LOGGING_CATEGORY(logCharacterWidget, "mdbot.gui.characterwidget")

CharacterWidget::CharacterWidget(Character* character, MovementManager* movementManager, QWidget* parent)
    : QWidget(parent), m_character(character), m_movementManager(movementManager)
{
    try
    {
        auto* mainLayout = new QVBoxLayout(this);

        // --- Блок основной информации ---
        auto* infoGroup = new QGroupBox(tr("Информация о персонаже"));
        auto* infoLayout = new QVBoxLayout();
        m_nameLabel = new QLabel(tr("Имя: -"), this);
        m_levelLabel = new QLabel(tr("Уровень: -"), this);
        m_healthLabel = new QLabel(tr("HP: - / -"), this);
        m_manaLabel = new QLabel(tr("Мана: - / -"), this);
        m_positionLabel = new QLabel(tr("Позиция: -"), this);
        m_mapIdLabel = new QLabel(tr("ID Карты: -"), this);  // Инициализация метки
        m_stateLabel = new QLabel(tr("Состояние: -"), this);
        infoLayout->addWidget(m_nameLabel);
        infoLayout->addWidget(m_levelLabel);
        infoLayout->addWidget(m_healthLabel);
        infoLayout->addWidget(m_manaLabel);
        infoLayout->addWidget(m_positionLabel);
        infoLayout->addWidget(m_mapIdLabel);  // Добавление в layout
        infoLayout->addWidget(m_stateLabel);
        infoGroup->setLayout(infoLayout);
        mainLayout->addWidget(infoGroup);

        // --- Блок управления обновлением ---
        auto* controlGroup = new QGroupBox(tr("Управление"));
        auto* controlLayout = new QHBoxLayout();
        m_updateButton = new QPushButton(tr("Обновить"), this);
        m_autoUpdateCheck = new QCheckBox(tr("Автообновление"), this);
        m_autoUpdateTimer = new QTimer(this);
        m_autoUpdateTimer->setInterval(1000);
        m_autoUpdateTimer->setSingleShot(false);
        controlLayout->addWidget(m_updateButton);
        controlLayout->addWidget(m_autoUpdateCheck);
        controlGroup->setLayout(controlLayout);
        mainLayout->addWidget(controlGroup);

        // --- Блок навигации (новый) ---
        auto* navGroup = new QGroupBox(tr("Тестовая навигация"));
        auto* navLayout = new QVBoxLayout();
        m_navSchoolButton = new QPushButton(tr("школа"), this);
        m_navEronaButton = new QPushButton(tr("Эрона"), this);
        navLayout->addWidget(m_navSchoolButton);
        navLayout->addWidget(m_navEronaButton);
        navGroup->setLayout(navLayout);
        mainLayout->addWidget(navGroup);

        mainLayout->addStretch();  // Добавляем растяжитель в конец
        setLayout(mainLayout);

        // --- Соединения сигналов и слотов ---
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

        // Соединения для навигационных кнопок
        connect(m_navSchoolButton, &QPushButton::clicked, this,
                [this]()
                {
                    if (!m_movementManager)
                    {
                        logError("MovementManager не инициализирован!");
                        return;
                    }
                    MovementSettings settings;
                    settings.navigationType = MovementSettings::NavigationType::MMap;
                    m_movementManager->moveTo(10150.19629f, -6004.603516f, 110.1543732f, settings);
                    qCInfo(logCharacterWidget) << "Отправлена команда навигации в точку 'школа'";
                });

        connect(m_navEronaButton, &QPushButton::clicked, this,
                [this]()
                {
                    if (!m_movementManager)
                    {
                        logError("MovementManager не инициализирован!");
                        return;
                    }
                    MovementSettings settings;
                    settings.navigationType = MovementSettings::NavigationType::MMap;
                    m_movementManager->moveTo(10347.58008f, -6358.060547f, 33.44028473f, settings);
                    qCInfo(logCharacterWidget) << "Отправлена команда навигации в точку 'Эрона'";
                });

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
    m_mapIdLabel->setText(tr("ID Карты: %1").arg(data.mapId));  // Обновление метки MapID
    m_stateLabel->setText(tr("Состояние: %1").arg(data.inCombat ? "В бою" : "Мирно"));
}

void CharacterWidget::logError(const QString& message)
{
    qCCritical(logCharacterWidget) << message;
    QMessageBox::critical(this, tr("Ошибка"), message);
}
