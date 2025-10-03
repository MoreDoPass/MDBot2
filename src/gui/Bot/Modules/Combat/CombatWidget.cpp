#include "CombatWidget.h"
#include <QFormLayout>
#include <QComboBox>
#include <QVariant>

CombatWidget::CombatWidget(QWidget* parent) : QWidget(parent)
{
    auto* layout = new QFormLayout(this);

    m_classComboBox = new QComboBox(this);
    m_specComboBox = new QComboBox(this);

    // --- Заполняем список классов ---
    // Текст для пользователя, а в данные (data) кладем enum для программы
    m_classComboBox->addItem(tr("Паладин"), QVariant::fromValue(CharacterClass::Paladin));
    m_classComboBox->addItem(tr("Воин"), QVariant::fromValue(CharacterClass::Warrior));
    m_classComboBox->addItem(tr("Рыцарь Смерти"), QVariant::fromValue(CharacterClass::DeathKnight));  // <-- ДОБАВЛЕНО

    layout->addRow(tr("Класс:"), m_classComboBox);
    layout->addRow(tr("Специализация:"), m_specComboBox);

    setLayout(layout);

    // --- Главное соединение для динамического обновления ---
    // Когда меняется класс, вызываем наш слот для обновления спеков
    connect(m_classComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &CombatWidget::onClassChanged);

    // --- Первоначальное заполнение ---
    // Сразу заполняем список спеков для класса, который выбран по умолчанию (Паладин)
    onClassChanged(m_classComboBox->currentIndex());
}

CharacterSpec CombatWidget::getSpec() const
{
    // Просто возвращаем enum, который мы сохранили в данных выбранного элемента
    return m_specComboBox->currentData().value<CharacterSpec>();
}

void CombatWidget::onClassChanged(int index)
{
    // Блокируем сигналы, чтобы не было лишних срабатываний при очистке
    const QSignalBlocker blocker(m_specComboBox);

    // Получаем класс, который сейчас выбран
    CharacterClass selectedClass = m_classComboBox->itemData(index).value<CharacterClass>();

    // Очищаем список спеков
    m_specComboBox->clear();

    // Заполняем список спеков в зависимости от выбранного класса
    switch (selectedClass)
    {
        case CharacterClass::Paladin:
            m_specComboBox->addItem(tr("Защита (Protection)"), QVariant::fromValue(CharacterSpec::PaladinProtection));
            m_specComboBox->addItem(tr("Воздаяние (Retribution)"),
                                    QVariant::fromValue(CharacterSpec::PaladinRetribution));
            m_specComboBox->addItem(tr("Свет (Holy)"), QVariant::fromValue(CharacterSpec::PaladinHoly));
            break;

        case CharacterClass::Warrior:
            m_specComboBox->addItem(tr("Оружие (Arms)"), QVariant::fromValue(CharacterSpec::WarriorArms));
            m_specComboBox->addItem(tr("Неистовство (Fury)"), QVariant::fromValue(CharacterSpec::WarriorFury));
            m_specComboBox->addItem(tr("Защита (Protection)"), QVariant::fromValue(CharacterSpec::WarriorProtection));
            break;

        case CharacterClass::DeathKnight:  // <-- НОВЫЙ КЛАСС
            m_specComboBox->addItem(tr("Кровь (Blood)"), QVariant::fromValue(CharacterSpec::DeathKnightBlood));
            m_specComboBox->addItem(tr("Лед (Frost)"), QVariant::fromValue(CharacterSpec::DeathKnightFrost));
            m_specComboBox->addItem(tr("Нечестивость (Unholy)"), QVariant::fromValue(CharacterSpec::DeathKnightUnholy));
            break;

        default:
            // Если для класса не заданы спеки, список будет пустым
            break;
    }
}