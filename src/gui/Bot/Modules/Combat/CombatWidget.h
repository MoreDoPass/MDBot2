#pragma once

#include <QWidget>
#include "core/Bot/Settings/BotSettings.h"  // Подключаем для CharacterSpec

// Прямые объявления
class QComboBox;

/**
 * @class CombatWidget
 * @brief Виджет для настроек, связанных с боем.
 * @details Позволяет пользователю выбрать класс и специализацию,
 *          которую бот будет использовать для построения ротации.
 */
class CombatWidget : public QWidget
{
    Q_OBJECT
   public:
    explicit CombatWidget(QWidget* parent = nullptr);

    /**
     * @brief Собирает настройку специализации из UI.
     * @return Enum CharacterSpec, соответствующий выбору пользователя.
     */
    CharacterSpec getSpec() const;

   private slots:
    /**
     * @brief Обновляет список специализаций при смене класса.
     * @param index Текущий индекс выбранного элемента в classComboBox.
     */
    void onClassChanged(int index);

   private:
    QComboBox* m_classComboBox;  ///< Выпадающий список для выбора класса
    QComboBox* m_specComboBox;   ///< Выпадающий список для выбора специализации
};