#include <QApplication>
#include "gui/mainwindow.h"
#include "core/MemoryManager/MemoryManager.h"

int main(int argc, char *argv[])
{
    MemoryManager memoryManager;
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}
