// --- НАЧАЛО ФАЙЛА gui/Bot/Modules/Grinding/GrindingWidget.h ---
#pragma once

#include <QWidget>
#include "core/Bot/Settings/GrindingSettings.h"  // <-- Подключаем нашу новую структуру настроек

// Прямые объявления для ускорения компиляции
class QLineEdit;
class QPushButton;
class ProfileManager;

/**
 * @class GrindingWidget
 * @brief Виджет для настройки параметров модуля "Гринд мобов".
 * @details Предоставляет пользователю интерфейс для выбора маршрута и указания
 *          ID мобов, которых необходимо атаковать.
 */
class GrindingWidget : public QWidget
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор.
     * @param parent Родительский виджет.
     */
    explicit GrindingWidget(ProfileManager* profileManager, QWidget* parent = nullptr);

    /**
     * @brief Собирает и возвращает настройки, введенные пользователем в этом виджете.
     * @return Структура GrindingSettings с актуальными данными.
     */
    GrindingSettings getSettings() const;

   private slots:
    /**
     * @brief Открывает диалоговое окно для выбора файла профиля (маршрута).
     */
    void onBrowseClicked();

   private:
    /// @brief Поле для отображения/ввода пути к файлу маршрута.
    QLineEdit* m_profilePathLineEdit;

    /// @brief Кнопка для вызова диалога выбора файла.
    QPushButton* m_browseButton;

    /// @brief Поле для ввода ID мобов через запятую.
    QLineEdit* m_npcIdsLineEdit;

    /// @brief Указатель на менеджер профилей, полученный извне.
    ProfileManager* m_profileManager;
};
// --- КОНЕЦ ФАЙЛА gui/Bot/Modules/Grinding/GrindingWidget.h ---