#include "SettingsWidget.h"
#include "core/BlacklistManager/BlacklistManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QComboBox>
#include <QListWidget>
#include <QPushButton>
#include <QVariant>
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logSettingsWidget, "mdbot.gui.settingswidget")

SettingsWidget::SettingsWidget(QWidget* parent) : QWidget(parent)
{
    auto* mainLayout = new QVBoxLayout(this);

    auto* movementGroup = new QGroupBox(tr("Настройки передвижения"));
    auto* formLayout = new QFormLayout();
    m_navigationTypeComboBox = new QComboBox(this);
    m_navigationTypeComboBox->addItem(tr("Только бег / маунт (Безопасно)"),
                                      QVariant::fromValue(MovementSettings::NavigationType::CtM_Only));
    m_navigationTypeComboBox->addItem(tr("Гибридный (Бег + Телепорт)"),
                                      QVariant::fromValue(MovementSettings::NavigationType::CtM_And_Teleport));
    m_navigationTypeComboBox->addItem(tr("Только телепорт (Быстро)"),
                                      QVariant::fromValue(MovementSettings::NavigationType::Teleport_Only));
    formLayout->addRow(tr("Стратегия передвижения:"), m_navigationTypeComboBox);
    movementGroup->setLayout(formLayout);
    mainLayout->addWidget(movementGroup);

    auto* blacklistGroup = new QGroupBox(tr("Постоянный черный список"));
    auto* blacklistLayout = new QVBoxLayout();

    m_blacklistWidget = new QListWidget(this);
    m_blacklistWidget->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_removeButton = new QPushButton(tr("Удалить выбранное"), this);

    blacklistLayout->addWidget(m_blacklistWidget);
    blacklistLayout->addWidget(m_removeButton);
    blacklistGroup->setLayout(blacklistLayout);
    mainLayout->addWidget(blacklistGroup, 1);

    setLayout(mainLayout);

    connect(m_removeButton, &QPushButton::clicked, this, &SettingsWidget::onRemoveFromBlacklistClicked);

    // Подключаем сигнал напрямую. Так как сигнал будет испускаться из того же потока,
    // что и GUI (из add/remove), нам не нужны никакие QueuedConnection.
    connect(&BlacklistManager::instance(), &BlacklistManager::blacklistUpdated, this,
            &SettingsWidget::refreshBlacklist);

    refreshBlacklist();
}

MovementSettings SettingsWidget::getSettings() const
{
    MovementSettings settings;
    settings.navigationType = m_navigationTypeComboBox->currentData().value<MovementSettings::NavigationType>();
    return settings;
}

void SettingsWidget::refreshBlacklist()
{
    const QSignalBlocker blocker(m_blacklistWidget);
    m_blacklistWidget->clear();

    const QSet<quint64> guids = BlacklistManager::instance().getBlacklistedGuids();
    for (const quint64 guid : guids)
    {
        m_blacklistWidget->addItem(QString::number(guid));
    }
    qCDebug(logSettingsWidget) << "Blacklist widget refreshed, item count:" << guids.size();
}

void SettingsWidget::onRemoveFromBlacklistClicked()
{
    const QList<QListWidgetItem*> selectedItems = m_blacklistWidget->selectedItems();
    if (selectedItems.isEmpty())
    {
        return;
    }

    qCInfo(logSettingsWidget) << "User requested to remove" << selectedItems.count() << "items from blacklist.";

    for (QListWidgetItem* item : selectedItems)
    {
        const QString guidStr = item->text();
        bool ok;
        const quint64 guid = guidStr.toULongLong(&ok);
        if (ok)
        {
            // Простой, прямой, неблокирующий вызов.
            BlacklistManager::instance().remove(guid);
        }
        else
        {
            qCWarning(logSettingsWidget) << "Failed to convert item text to GUID:" << guidStr;
        }
    }
}