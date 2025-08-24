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
        // Создаём объект Bot с PID процесса и именем компьютера (только через new!)
        Bot* bot = new Bot(static_cast<qint64>(info.pid), QString::fromStdWString(info.name), computerName);
        if (!bot)
        {
            qCCritical(mainWindowLog) << "Не удалось создать объект Bot для PID:" << info.pid;
            LogWindow::appendLog(QString("Не удалось создать объект Bot для PID: %1").arg(info.pid));
            QMessageBox::critical(this, "Ошибка", QString("Не удалось создать объект Bot для PID: %1").arg(info.pid));
            return;
        }

        // Создаём поток для бота
        QThread* botThread = new QThread(this);  // Поток удалится вместе с MainWindow
        bot->moveToThread(botThread);

        // УДАЛЕНО: connect(botThread, &QThread::started, bot, &Bot::run);

        connect(bot, &Bot::finished, botThread, &QThread::quit);
        connect(bot, &Bot::finished, bot, &Bot::deleteLater);
        connect(botThread, &QThread::finished, botThread, &QThread::deleteLater);

        // Запускаем поток. Бот теперь просто ждет команд в этом потоке.
        botThread->start();

        // Создаём виджет BotWidget для управления этим ботом
        BotWidget* botWidget = nullptr;
        try
        {
            botWidget = new BotWidget(bot, this);
        }
        catch (const std::exception& ex)
        {
            qCCritical(mainWindowLog) << "Ошибка при создании BotWidget:" << ex.what();
            LogWindow::appendLog(QString("Ошибка при создании BotWidget: %1").arg(ex.what()));
            QMessageBox::critical(this, "Ошибка", QString("Ошибка при создании BotWidget: %1").arg(ex.what()));
            return;
        }
        catch (...)
        {
            qCCritical(mainWindowLog) << "Неизвестная ошибка при создании BotWidget";
            LogWindow::appendLog("Неизвестная ошибка при создании BotWidget");
            QMessageBox::critical(this, "Ошибка", "Неизвестная ошибка при создании BotWidget");
            return;
        }

        // Добавляем вкладку с именем процесса и PID
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
