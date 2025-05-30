#pragma once

#include <QWidget>
#include <QLoggingCategory>
#include <QTabWidget>
#include "gui/Bot/CharacterWidget/CharacterWidget.h"
#include "gui/Bot/MainWidget/MainWidget.h"

class Bot;

/**
 * @brief Категория логирования для BotWidget.
 */
Q_DECLARE_LOGGING_CATEGORY(logBotWidget)

/**
 * @brief Виджет для отображения и управления одним ботом (Bot).
 *
 * Отображает информацию о процессе, персонаже и предоставляет элементы управления ботом.
 */
class BotWidget : public QWidget
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор BotWidget.
     * @param bot Указатель на объект Bot.
     * @param parent Родительский виджет.
     */
    explicit BotWidget(Bot* bot, QWidget* parent = nullptr);
    ~BotWidget();

   private:
    Bot* m_bot;                                    ///< Указатель на объект Bot (не shared_ptr!)
    MainWidget* m_mainWidget = nullptr;            ///< Виджет для отображения данных основного интерфейса
    CharacterWidget* m_characterWidget = nullptr;  ///< Виджет для отображения данных персонажа
    QTabWidget* m_tabWidget = nullptr;             ///< Виджет для отображения вкладок

    // Пример UI-элементов (можно расширять)
    // QLabel* m_pidLabel;
    // QLabel* m_characterNameLabel;
    // QPushButton* m_startButton;
    // ...
};