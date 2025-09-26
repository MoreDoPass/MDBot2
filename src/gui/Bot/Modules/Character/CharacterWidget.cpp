#include "CharacterWidget.h"
#include <QVBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QStringList>  // Для удобного форматирования списков

Q_LOGGING_CATEGORY(logCharacterWidget, "mdbot.gui.characterwidget")

CharacterWidget::CharacterWidget(Character* character, QWidget* parent) : QWidget(parent), m_character(character)
{
    if (!m_character)
    {
        // Если нам не передали объект Character, виджет бесполезен.
        logError(tr("Character не инициализирован! Виджет не будет работать."));
        return;
    }

    try
    {
        auto* mainLayout = new QVBoxLayout(this);

        // --- Блок основной информации ---
        auto* infoGroup = new QGroupBox(tr("Информация о персонаже"));
        auto* infoLayout = new QGridLayout();  // Используем QGridLayout для красивого выравнивания

        infoLayout->addWidget(new QLabel(tr("GUID:")), 0, 0);
        m_guidLabel = new QLabel("-");
        infoLayout->addWidget(m_guidLabel, 0, 1);

        infoLayout->addWidget(new QLabel(tr("Уровень:")), 1, 0);
        m_levelLabel = new QLabel("-");
        infoLayout->addWidget(m_levelLabel, 1, 1);

        infoLayout->addWidget(new QLabel(tr("Здоровье:")), 2, 0);
        m_healthLabel = new QLabel("-");
        infoLayout->addWidget(m_healthLabel, 2, 1);

        infoLayout->addWidget(new QLabel(tr("Мана:")), 3, 0);
        m_manaLabel = new QLabel("-");
        infoLayout->addWidget(m_manaLabel, 3, 1);

        infoLayout->addWidget(new QLabel(tr("Позиция:")), 4, 0);
        m_positionLabel = new QLabel("-");
        infoLayout->addWidget(m_positionLabel, 4, 1);

        // --- Новые поля для отладки ---
        infoLayout->addWidget(new QLabel(tr("Ауры:")), 5, 0);
        m_aurasLabel = new QLabel("-");
        m_aurasLabel->setWordWrap(true);  // Разрешаем перенос строк
        infoLayout->addWidget(m_aurasLabel, 5, 1);

        infoLayout->addWidget(new QLabel(tr("Кулдауны:")), 6, 0);
        m_cooldownsLabel = new QLabel("-");
        m_cooldownsLabel->setWordWrap(true);
        infoLayout->addWidget(m_cooldownsLabel, 6, 1);

        infoGroup->setLayout(infoLayout);
        mainLayout->addWidget(infoGroup);

        // --- Блок управления ---
        m_refreshButton = new QPushButton(tr("Обновить данные"), this);
        mainLayout->addWidget(m_refreshButton);

        mainLayout->addStretch();  // Добавляем "пружинку", чтобы все прижалось кверху
        setLayout(mainLayout);

        // --- Соединение сигнала и слота ---
        // Соединяем нажатие кнопки с нашим слотом onRefreshClicked
        connect(m_refreshButton, &QPushButton::clicked, this, &CharacterWidget::onRefreshClicked);

        // Выполняем первичное обновление, чтобы показать хоть какие-то данные при запуске
        onRefreshClicked();
    }
    catch (const std::exception& ex)
    {
        logError(tr("Ошибка при создании CharacterWidget: %1").arg(ex.what()));
    }
}

CharacterWidget::~CharacterWidget() = default;

void CharacterWidget::onRefreshClicked()
{
    // Слот просто вызывает основной метод обновления UI
    updateUi();
}

void CharacterWidget::updateUi()
{
    // Проверяем, что наш источник данных все еще валиден
    if (!m_character) return;

    // Напрямую обращаемся к "живым" геттерам объекта Character
    m_guidLabel->setText(QString("0x%1").arg(m_character->getGuid(), 0, 16));
    m_levelLabel->setText(QString::number(m_character->getLevel()));
    m_healthLabel->setText(QString("%1 / %2").arg(m_character->getHealth()).arg(m_character->getMaxHealth()));
    m_manaLabel->setText(QString("%1 / %2").arg(m_character->getMana()).arg(m_character->getMaxMana()));

    const Vector3 pos = m_character->getPosition();
    m_positionLabel->setText(
        QString("X=%1 Y=%2 Z=%3").arg(pos.x, 0, 'f', 2).arg(pos.y, 0, 'f', 2).arg(pos.z, 0, 'f', 2));

    QStringList aurasList;
    // Вызываем новый геттер
    for (int32_t auraId : m_character->getAuras())
    {
        aurasList << QString::number(auraId);
    }
    m_aurasLabel->setText(aurasList.join(", "));
    if (aurasList.isEmpty()) m_aurasLabel->setText(tr("-"));  // Показываем прочерк, если пусто

    QStringList cooldownsList;
    // Вызываем новый геттер
    for (uint32_t cdId : m_character->getCooldowns())
    {
        cooldownsList << QString::number(cdId);
    }
    m_cooldownsLabel->setText(cooldownsList.join(", "));
    if (cooldownsList.isEmpty()) m_cooldownsLabel->setText(tr("-"));  // Показываем прочерк, если пусто
}

void CharacterWidget::logError(const QString& message)
{
    qCCritical(logCharacterWidget) << message;
    QMessageBox::critical(this, tr("Ошибка"), message);
}