#include "LogWindow.h"
#include <QDateTime>
#include <QHBoxLayout>

Q_LOGGING_CATEGORY(logWindowLog, "gui.logwindow")

LogWindow* LogWindow::instance(QWidget* parent)
{
    static LogWindow* s_instance = nullptr;
    if (!s_instance)
    {
        s_instance = new LogWindow(parent);
    }
    return s_instance;
}

void LogWindow::appendLog(const QString& message)
{
    LogWindow* win = LogWindow::instance();
    if (!win->logEdit)
    {
        win->logQueue.push_back(message);
        return;
    }
    if (!win->isVisible())
    {
        win->logQueue.push_back(message);
    }
    else
    {
        win->logEdit->append(message);  // Выводим только то, что пришло из messageHandler
    }
}

void LogWindow::flushQueue()
{
    for (const auto& msg : logQueue)
    {
        logEdit->append(msg);  // Без добавления времени
    }
    logQueue.clear();
}

LogWindow::LogWindow(QWidget* parent) : QWidget(parent)
{
    setWindowTitle("Логи приложения");
    resize(600, 400);
    logEdit = new QTextEdit(this);
    logEdit->setReadOnly(true);
    clearButton = new QPushButton("Очистить", this);
    enableLoggingCheckBox = new QCheckBox("Включить логирование", this);
    enableLoggingCheckBox->setChecked(true);
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->addWidget(enableLoggingCheckBox);
    layout->addWidget(logEdit);
    layout->addWidget(clearButton);
    setLayout(layout);
    connect(clearButton, &QPushButton::clicked, logEdit, &QTextEdit::clear);
    connect(enableLoggingCheckBox, &QCheckBox::toggled, this,
            [](bool checked)
            {
                try
                {
                    initLogging(checked, QStringLiteral("MDBot2.log"));
                }
                catch (const std::exception& ex)
                {
                    qCCritical(logWindowLog) << "Ошибка при переключении логирования:" << ex.what();
                }
            });
}

void LogWindow::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    flushQueue();
}
