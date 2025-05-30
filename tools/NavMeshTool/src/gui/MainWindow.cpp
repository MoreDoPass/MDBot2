#include "MainWindow.h"
#include "core/MpqManager/MpqManager.h"  // Подключаем заголовок MpqManager

#include <QFileDialog>
#include <QMenuBar>
#include <QStatusBar>
#include <QMessageBox>
#include <QApplication>  // Для qApp
#include <QLoggingCategory>

// Определяем или переиспользуем категорию логирования
Q_LOGGING_CATEGORY(logMainWindow, "navmesh.gui.mainwindow")

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ui(nullptr)  // Если не используется .ui файл, можно убрать или инициализировать ui = new Ui::MainWindow;
                   // ui->setupUi(this);
      ,
      m_mpqManager(new MpqManager(this))  // Создаем MpqManager, делаем MainWindow его родителем
{
    // Если используете .ui файл, раскомментируйте:
    // ui = new Ui::MainWindow;
    // ui->setupUi(this);

    // Если UI создается кодом:
    setupUiElements();
    createActions();
    createMenus();
    createStatusBar();

    setWindowTitle(tr("NavMesh Tool"));
    resize(800, 600);

    qCInfo(logMainWindow) << "MainWindow_navmesh created and initialized.";
}

MainWindow::~MainWindow()
{
    // delete m_mpqManager; // Qt позаботится об удалении, так как MainWindow - родитель
    if (ui)  // Если используется .ui файл
        delete ui;
    qCInfo(logMainWindow) << "MainWindow_navmesh destroyed.";
}

void MainWindow::setupUiElements()
{
    // Здесь можно добавлять элементы UI кодом, если не используется .ui файл
    // Например, создать центральный виджет, лайауты, кнопки и т.д.
    // QWidget *centralWidget = new QWidget(this);
    // setCentralWidget(centralWidget);
    // QVBoxLayout *layout = new QVBoxLayout(centralWidget);
    // ...
}

void MainWindow::createActions()
{
    // Пример создания действия
    // openAction = new QAction(tr("&Open MPQ..."), this);
    // openAction->setShortcuts(QKeySequence::Open);
    // openAction->setStatusTip(tr("Open an MPQ archive"));
    // connect(openAction, &QAction::triggered, this, &MainWindow::openMpqArchive);
}

void MainWindow::createMenus()
{
    // fileMenu = menuBar()->addMenu(tr("&File"));
    // fileMenu->addAction(openAction);
    // ...
    // fileMenu->addSeparator();
    // fileMenu->addAction(exitAction); // exitAction нужно будет создать аналогично openAction
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::openMpqArchive()
{
    QString filePath = QFileDialog::getOpenFileName(this, tr("Open MPQ Archive"),
                                                    "",  // Начальная директория
                                                    tr("MPQ Archives (*.mpq);;All Files (*)"));

    if (!filePath.isEmpty())
    {
        qCInfo(logMainWindow) << "Attempting to open MPQ archive:" << filePath;
        // TODO: Вызвать метод m_mpqManager для загрузки архива
        // bool success = m_mpqManager->loadArchive(filePath.toStdString()); // filePath.toStdWString() если MpqManager
        // ожидает wstring if (success) {
        //     statusBar()->showMessage(tr("MPQ archive loaded: %1").arg(filePath));
        //     // TODO: Обновить UI (например, список файлов)
        // } else {
        //     QMessageBox::warning(this, tr("Error"), tr("Could not load MPQ archive: %1").arg(filePath));
        //     statusBar()->showMessage(tr("Failed to load MPQ archive."));
        // }
    }
}
