// ФАЙЛ: src/gui/Bot/Modules/Main/MainWidget.h

#pragma once

#include <QWidget>
#include <QLoggingCategory>
#include "core/Bot/Settings/BotSettings.h"  // <-- Подключаем наш "контракт"

// Прямые объявления, чтобы не включать лишние заголовки
class Bot;
class QPushButton;
class QLabel;
class QComboBox;

Q_DECLARE_LOGGING_CATEGORY(logMainWidget)

/**
 * @brief Виджет для управления основным состоянием бота (старт/стоп, статус).
 */
class MainWidget : public QWidget
{
    Q_OBJECT
   public:
    explicit MainWidget(Bot* bot, QWidget* parent = nullptr);
    ~MainWidget() override;

   signals:
    /**
     * @brief Сигнал, который отправляется, когда пользователь нажал "Старт".
     * @param type Тип модуля, который нужно запустить.
     */
    void startRequested(ModuleType type);
    /**
     * @brief Сигнал, когда пользователь нажал "Стоп".
     */
    void stopRequested();

   private slots:
    void onStartClicked();
    void onStopClicked();
    void onBotFinished();

    /**
     * @brief Слот, вызываемый при нажатии на кнопку "В ЧС тек. цель".
     * @details Получает у текущего бота GUID его цели и отправляет команду
     *          на добавление в BlacklistManager.
     */
    void onBlacklistCurrentTargetClicked();

   private:
    Bot* m_bot = nullptr;
    QPushButton* m_startButton = nullptr;
    QPushButton* m_stopButton = nullptr;
    QPushButton* m_blacklistButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QComboBox* m_moduleComboBox = nullptr;  // Выпадающий список для выбора модуля

    void updateStatus(const QString& status, bool error = false);
};