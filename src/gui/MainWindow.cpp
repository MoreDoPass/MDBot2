#include "gui/MainWindow.h"
#include "gui/ProcessManager/ProcessListDialog.h"
#include "gui/Logging/LogWindow.h"
#include "gui/Bot/BotWidget.h"
#include <memory>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QWidget>
#include <QLabel>
#include <QLoggingCategory>
#include <QThread>
#include "core/Bot/Bot.h"
Q_LOGGING_CATEGORY(mainWindowLog, "gui.mainwindow")

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle("MDBot2 Main Window");
    resize(800, 600);

    // Создаём меню
    QMenuBar* menuBar = new QMenuBar(this);
    QMenu* processMenu = menuBar->addMenu("Процессы");
    QAction* addProcessAction = processMenu->addAction("Добавить процесс");
    QMenu* logMenu = menuBar->addMenu("Логи");
    QAction* showLogAction = logMenu->addAction("Открыть лог");
    setMenuBar(menuBar);
    connect(addProcessAction, &QAction::triggered, this, &MainWindow::onAddProcess);
    connect(showLogAction, &QAction::triggered, this, &MainWindow::onShowLogWindow);

    // Создаём QTabWidget для вкладок
    tabWidget = new QTabWidget(this);
    setCentralWidget(tabWidget);

    qCInfo(mainWindowLog) << "Main window and menu initialized.";
    LogWindow::appendLog("Main window started.");
}

MainWindow::~MainWindow() = default;

void MainWindow::onAddProcess()
{
    try
    {
        ProcessListDialog dlg(this);
        if (dlg.exec() == QDialog::Accepted)
        {
            ProcessInfo info = dlg.selectedProcess();
            QString computerName = dlg.computerName();  // <-- Получаем имя компьютера из диалога

            if (info.pid != 0)
            {
                addProcessTab(info, computerName);  // <-- Передаем его дальше
                qCInfo(mainWindowLog) << "Process added PID:" << info.pid
                                      << ", name:" << QString::fromStdWString(info.name)
                                      << ", computerName:" << computerName;
                LogWindow::appendLog(QString("Process added: PID %1, name %2, computerName: %3")
                                         .arg(info.pid)
                                         .arg(QString::fromStdWString(info.name))
                                         .arg(computerName));
            }
            else
            {
                qCWarning(mainWindowLog) << "No process selected by user.";
                LogWindow::appendLog("No process selected by user.");
            }
        }
        else
        {
            qCInfo(mainWindowLog) << "Process selection dialog closed by user.";
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(mainWindowLog) << "Error adding process:" << ex.what();
        LogWindow::appendLog(QString("Error adding process: %1").arg(ex.what()));
        QMessageBox::critical(this, "Error", "Failed to add process: " + QString::fromUtf8(ex.what()));
    }
}

void MainWindow::onShowLogWindow()
{
    LogWindow::instance()->show();
    LogWindow::instance()->raise();
    LogWindow::instance()->activateWindow();
}

void MainWindow::addProcessTab(const ProcessInfo& info, const QString& computerName)
{
    try
    {
        // 1. Создаём объект Bot. Он сам позаботится о своем потоке.
        // Мы делаем его дочерним для BotWidget, чтобы он удалился вместе с вкладкой.
        Bot* bot = new Bot(static_cast<qint64>(info.pid), QString::fromStdWString(info.name), computerName);

        // 2. Создаём виджет BotWidget для управления этим ботом
        BotWidget* botWidget = new BotWidget(bot, this);
        // Устанавливаем bot дочерним объектом для botWidget.
        // Когда вкладка (botWidget) закроется, bot будет автоматически удален.
        bot->setParent(botWidget);

        // --- УДАЛЕНА ВСЯ СТАРАЯ ЛОГИКА УПРАВЛЕНИЯ ПОТОКОМ ---
        // QThread* botThread = new QThread(this);
        // bot->moveToThread(botThread);
        // connect(bot, &Bot::finished, botThread, &QThread::quit);
        // connect(bot, &Bot::finished, bot, &Bot::deleteLater); // <-- ГЛАВНАЯ ОШИБКА УДАЛЕНА
        // connect(botThread, &QThread::finished, botThread, &QThread::deleteLater);
        // botThread->start();

        // 3. Добавляем вкладку с готовым виджетом
        QString tabName = QString::fromStdWString(info.name) + QString(" [%1]").arg(info.pid);
        tabWidget->addTab(botWidget, tabName);
        qCInfo(mainWindowLog) << "Вкладка для бота успешно добавлена: " << tabName;
        LogWindow::appendLog(QString("Вкладка для бота успешно добавлена: %1").arg(tabName));
    }
    catch (const std::exception& ex)
    {
        qCCritical(mainWindowLog) << "Ошибка при добавлении вкладки бота:" << ex.what();
        LogWindow::appendLog(QString("Ошибка при добавлении вкладки бота: %1").arg(ex.what()));
        QMessageBox::critical(this, "Ошибка", "Ошибка при добавлении вкладки бота: " + QString::fromUtf8(ex.what()));
    }
    catch (...)
    {
        qCCritical(mainWindowLog) << "Неизвестная ошибка при добавлении вкладки бота";
        LogWindow::appendLog("Неизвестная ошибка при добавлении вкладки бота");
        QMessageBox::critical(this, "Ошибка", "Неизвестная ошибка при добавлении вкладки бота");
    }
}
