#include "SettingsWidget.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QComboBox>  // <-- Добавляем, если его не было
#include <QVariant>

// enum class TempMovementType { Teleport, GroundMount }; // <-- УДАЛЯЕМ ЭТУ СТРОКУ

SettingsWidget::SettingsWidget(QWidget* parent) : QWidget(parent)
{
    auto* mainLayout = new QVBoxLayout(this);
    auto* settingsGroup = new QGroupBox(tr("Настройки передвижения"));
    auto* formLayout = new QFormLayout();

    m_navigationTypeComboBox = new QComboBox(this);
    // Заполняем список в точном соответствии с нашим enum'ом NavigationType
    m_navigationTypeComboBox->addItem(tr("Только бег / маунт (Безопасно)"),
                                      QVariant::fromValue(MovementSettings::NavigationType::CtM_Only));
    m_navigationTypeComboBox->addItem(tr("Гибридный (Бег + Телепорт)"),
                                      QVariant::fromValue(MovementSettings::NavigationType::CtM_And_Teleport));
    m_navigationTypeComboBox->addItem(tr("Только телепорт (Быстро)"),
                                      QVariant::fromValue(MovementSettings::NavigationType::Teleport_Only));

    formLayout->addRow(tr("Стратегия передвижения:"), m_navigationTypeComboBox);

    settingsGroup->setLayout(formLayout);
    mainLayout->addWidget(settingsGroup);
    mainLayout->addStretch();
    setLayout(mainLayout);
}

// --- ИЗМЕНЕНИЕ: Возвращаем правильную структуру ---
MovementSettings SettingsWidget::getSettings() const
{
    MovementSettings settings;
    // Просто получаем данные типа NavigationType из выпадающего списка.
    settings.navigationType = m_navigationTypeComboBox->currentData().value<MovementSettings::NavigationType>();
    // В будущем здесь можно будет считывать значения из других элементов UI
    // settings.useGroundMount = m_useMountCheckBox->isChecked();
    return settings;
}