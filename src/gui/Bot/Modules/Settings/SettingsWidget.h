// ФАЙЛ: src/gui/Bot/Modules/Settings/SettingsWidget.h

#pragma once
#include <QWidget>
#include "core/Bot/Settings/BotSettings.h"  // <-- Подключаем наш "контракт"

class QComboBox;

/**
 * @brief Виджет для глобальных настроек бота.
 */
class SettingsWidget : public QWidget
{
    Q_OBJECT
   public:
    explicit SettingsWidget(QWidget* parent = nullptr);

    /**
     * @brief Собирает все глобальные настройки из UI в одну структуру.
     * @return Структура GlobalSettings с текущими значениями из виджета.
     */
    MovementSettings getSettings() const;  // <-- ИЗМЕНЕНО ЗДЕСЬ

   private:
    QComboBox* m_navigationTypeComboBox;
};