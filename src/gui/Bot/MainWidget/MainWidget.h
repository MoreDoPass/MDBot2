#pragma once

#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QLoggingCategory>

class Bot;

/**
 * @brief Категория логирования для MainWidget.
 */
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
     * @brief Сигнал, когда пользователь нажал "Старт".
     */
    void startRequested();
    /**
     * @brief Сигнал, когда пользователь нажал "Стоп".
     */
    void stopRequested();

   private slots:
    void onStartClicked();
    void onStopClicked();
    void onBotFinished();

   private:
    Bot* m_bot = nullptr;
    QPushButton* m_startButton = nullptr;
    QPushButton* m_stopButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    void updateStatus(const QString& status, bool error = false);
};
