// ФАЙЛ: src/gui/Bot/Modules/Settings/SettingsWidget.h

#pragma once
#include <QWidget>
#include "core/Bot/Settings/BotSettings.h"  // <-- Подключаем наш "контракт"

// Прямые объявления для ускорения компиляции
class QComboBox;
class QListWidget;
class QPushButton;

/**
 * @brief Виджет для глобальных настроек бота.
 * @details Содержит настройки передвижения и панель управления постоянным черным списком.
 */
class SettingsWidget : public QWidget
{
    Q_OBJECT
   public:
    explicit SettingsWidget(QWidget* parent = nullptr);

    /**
     * @brief Собирает все настройки передвижения из UI в одну структуру.
     * @return Структура MovementSettings с текущими значениями из виджета.
     */
    MovementSettings getSettings() const;

   private slots:
    /**
     * @brief Обновляет (полностью перезаполняет) список GUID'ов в виджете.
     * @details Этот слот вызывается автоматически при изменении в BlacklistManager.
     */
    void refreshBlacklist();

    /**
     * @brief Вызывается при нажатии кнопки "Удалить".
     * @details Удаляет все выделенные GUID'ы из черного списка.
     */
    void onRemoveFromBlacklistClicked();

   private:
    // --- Элементы для настроек передвижения ---
    QComboBox* m_navigationTypeComboBox;

    // --- Элементы для управления черным списком ---
    QListWidget* m_blacklistWidget;  ///< Виджет для отображения списка забаненных GUID'ов
    QPushButton* m_removeButton;     ///< Кнопка для удаления выделенного GUID'а из списка
};