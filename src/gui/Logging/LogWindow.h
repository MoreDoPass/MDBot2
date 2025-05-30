#pragma once
#include <QWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLoggingCategory>
#include <QCheckBox>
#include <vector>

#include "core/Logging/Logging.h"

/**
 * @brief Окно для отображения логов приложения.
 */
class LogWindow : public QWidget
{
    Q_OBJECT
   public:
    static LogWindow* instance(QWidget* parent = nullptr);
    static void appendLog(const QString& message);

   private:
    explicit LogWindow(QWidget* parent = nullptr);
    QTextEdit* logEdit;
    QPushButton* clearButton;
    QCheckBox* enableLoggingCheckBox;
    std::vector<QString> logQueue;  // Очередь для накопления логов
    void flushQueue();              // Выводит накопленные логи в окно
   protected:
    void showEvent(QShowEvent* event) override;
};

Q_DECLARE_LOGGING_CATEGORY(logWindowLog)
