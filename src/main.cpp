#include <QApplication>
#include "gui/MainWindow.h"
#include "gui/Logging/LogWindow.h"
#include "core/Logging/Logging.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    // Инициализируем логирование сразу, чтобы все логи шли в LogWindow и/или файл
    initLogging(true, QStringLiteral("MDBot2.log"));
    setLogCallback(LogWindow::appendLog);
    // Гарантируем создание LogWindow (singleton)
    LogWindow::instance();
    MainWindow w;
    w.show();
    return app.exec();
}
