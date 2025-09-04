#pragma once

#include <QWidget>
#include <QLoggingCategory>
#include <QPoint>  // <-- ДОБАВЛЕНО: для позиции курсора
#include "Shared/Data/SharedData.h"

// Прямые объявления для ускорения компиляции
class Bot;
class QPushButton;
class QTableView;
class QStandardItemModel;

Q_DECLARE_LOGGING_CATEGORY(logDebugWidget)

class DebugWidget : public QWidget
{
    Q_OBJECT

   public:
    explicit DebugWidget(Bot* bot, QWidget* parent = nullptr);
    ~DebugWidget() override;

   public slots:
    /**
     * @brief Слот для приема готовых данных от бота.
     * @param data Структура с данными для отображения.
     */
    void onDebugDataReady(const SharedData& data);

   signals:
    /**
     * @brief Сигнал, который виджет испускает, когда пользователь
     *        нажимает кнопку "Обновить".
     */
    void refreshRequested();

   private slots:
    /**
     * @brief Слот, вызываемый при нажатии на кнопку "Обновить".
     */
    void onRefreshClicked();

    /**
     * @brief Слот для отображения контекстного меню таблицы.
     * @param pos Позиция, в которой был сделан клик.
     */
    void showContextMenu(const QPoint& pos);

   private:
    Bot* m_bot;
    QPushButton* m_refreshButton = nullptr;
    QTableView* m_objectsTable = nullptr;
    QStandardItemModel* m_objectsModel = nullptr;

    /// @brief Храним последние полученные данные, чтобы иметь к ним доступ из контекстного меню.
    SharedData m_lastReceivedData;
};