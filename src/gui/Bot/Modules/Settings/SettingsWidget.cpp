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
    auto* settingsGroup = new QGroupBox(tr("Глобальные настройки"));
    auto* formLayout = new QFormLayout();

    m_movementTypeComboBox = new QComboBox(this);
    // Заполняем список вручную: Текст для пользователя, данные (enum) для нас.
    // Это просто, надежно и не требует Qt-магии.
    m_movementTypeComboBox->addItem(tr("Телепортация"), QVariant::fromValue(MovementType::Teleport));
    m_movementTypeComboBox->addItem(tr("Наземный маунт"), QVariant::fromValue(MovementType::GroundMount));
    m_movementTypeComboBox->addItem(tr("Летающий маунт (в разработке)"),
                                    QVariant::fromValue(MovementType::FlyingMount));
    m_movementTypeComboBox->setItemData(2, false, Qt::ItemIsEnabled);  // Делаем последнюю опцию неактивной

    formLayout->addRow(tr("Метод передвижения:"), m_movementTypeComboBox);

    settingsGroup->setLayout(formLayout);
    mainLayout->addWidget(settingsGroup);
    mainLayout->addStretch();
    setLayout(mainLayout);
}

// --- ИЗМЕНЕНИЕ: Возвращаем правильную структуру ---
GlobalSettings SettingsWidget::getSettings() const
{
    GlobalSettings settings;
    // Просто получаем данные типа MovementType из выпадающего списка.
    settings.movementType = m_movementTypeComboBox->currentData().value<MovementType>();
    return settings;
}