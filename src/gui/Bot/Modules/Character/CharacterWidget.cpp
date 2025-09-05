#include "CharacterWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QGroupBox>
#include <QLabel>  // Убедимся, что все заголовки на месте
#include <QPushButton>
#include <QCheckBox>
#include <QTimer>

Q_LOGGING_CATEGORY(logCharacterWidget, "mdbot.gui.characterwidget")

CharacterWidget::CharacterWidget(Character* character, QWidget* parent)
    : QWidget(parent), m_character(character)  // Убираем movementManager, он здесь не используется
{
    try
    {
        auto* mainLayout = new QVBoxLayout(this);

        // --- Блок основной информации ---
        auto* infoGroup = new QGroupBox(tr("Информация о персонаже"));
        auto* infoLayout = new QVBoxLayout();
        m_nameLabel = new QLabel(tr("Имя: - (GUID: -)"), this);  // <-- ИЗМЕНЕНО: Имени пока нет, выводим GUID
        m_levelLabel = new QLabel(tr("Уровень: -"), this);
        m_healthLabel = new QLabel(tr("HP: - / -"), this);
        m_manaLabel = new QLabel(tr("Мана: - / -"), this);
        m_positionLabel = new QLabel(tr("Позиция: -"), this);
        m_mapIdLabel =
            new QLabel(tr("ID Карты: - (Not implemented)"), this);  // <-- ИЗМЕНЕНО: Помечаем, что пока не реализовано
        m_stateLabel =
            new QLabel(tr("Состояние: - (Not implemented)"), this);  // <-- ИЗМЕНЕНО: Помечаем, что пока не реализовано

        infoLayout->addWidget(m_nameLabel);
        infoLayout->addWidget(m_levelLabel);
        infoLayout->addWidget(m_healthLabel);
        infoLayout->addWidget(m_manaLabel);
        infoLayout->addWidget(m_positionLabel);
        infoLayout->addWidget(m_mapIdLabel);
        infoLayout->addWidget(m_stateLabel);
        infoGroup->setLayout(infoLayout);
        mainLayout->addWidget(infoGroup);

        // --- УДАЛЕН БЛОК УПРАВЛЕНИЯ ОБНОВЛЕНИЕМ ---
        // Кнопка "Обновить" и автообновление больше не нужны,
        // так как данные теперь поступают автоматически через сигнал dataChanged.
        // Это упрощает GUI и делает его более отзывчивым.

        mainLayout->addStretch();
        setLayout(mainLayout);

        // --- Соединения сигналов и слотов ---
        if (m_character)
        {
            // Это единственное соединение, которое нам теперь нужно.
            // Как только данные в Character изменятся, он отправит сигнал, и мы обновим UI.
            connect(m_character, &Character::dataChanged, this, &CharacterWidget::onCharacterDataChanged);
            // Первичное обновление UI текущими (скорее всего, нулевыми) данными
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

// --- МЕТОД onUpdateClicked УДАЛЕН ---
// Больше не нужен, так как нет кнопки "Обновить".
/*
void CharacterWidget::onUpdateClicked()
{
    // ...
}
*/

// --- МЕТОД onAutoUpdateTimeout УДАЛЕН ---
// Больше не нужен, так как нет таймера автообновления.
/*
void CharacterWidget::onAutoUpdateTimeout()
{
    // ...
}
*/

void CharacterWidget::onCharacterDataChanged(const CharacterData& data)
{
    updateUi(data);
}

void CharacterWidget::updateUi(const CharacterData& data)
{
    // --- ИСПОЛЬЗУЕМ ТОЛЬКО ТЕ ПОЛЯ, ЧТО ЕСТЬ В PlayerData ---
    m_nameLabel->setText(tr("GUID: %1").arg(data.guid, 0, 16));  // Имени пока нет, выводим GUID в HEX
    m_levelLabel->setText(tr("Уровень: %1").arg(data.level));
    m_healthLabel->setText(tr("HP: %1 / %2").arg(data.health).arg(data.maxHealth));
    m_manaLabel->setText(tr("Мана: %1 / %2").arg(data.mana).arg(data.maxMana));
    m_positionLabel->setText(tr("Позиция: X=%1 Y=%2 Z=%3")
                                 .arg(data.position.x, 0, 'f', 2)
                                 .arg(data.position.y, 0, 'f', 2)
                                 .arg(data.position.z, 0, 'f', 2));

    // Поля mapId и inCombat пока не передаются, оставляем заглушки.
    // m_mapIdLabel->setText(tr("ID Карты: %1").arg(data.mapId));
    // m_stateLabel->setText(tr("Состояние: %1").arg(data.inCombat ? "В бою" : "Мирно"));
}

void CharacterWidget::logError(const QString& message)
{
    qCCritical(logCharacterWidget) << message;
    QMessageBox::critical(this, tr("Ошибка"), message);
}