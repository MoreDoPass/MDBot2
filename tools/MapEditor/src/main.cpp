#include <QLoggingCategory>
#include <QApplication>
#include "gui/MainWindow.h"  // Предполагаем, что MainWindow будет в gui

int main(int argc, char *argv[])
{
    // Включаем вывод для нашей категории логирования и для некоторых категорий Qt по OpenGL
    QLoggingCategory::setFilterRules(
        QStringLiteral("*.debug=false\n"                      // Отключаем все по умолчанию
                       "qt.mapeditor.map3dview.debug=true\n"  // Включаем нашу основную категорию для Map3DView
                       "gui.mainWindow.debug=true\n"          // Предполагая, что у вас есть логгер для MainWindow
                       // "qt.mapeditor.openglwidget.debug=true\n" // Если есть отдельная категория для openglwidget
                       // "qt.opengl.debug=true\n"                 // Общие логи OpenGL от Qt, могут быть полезны
                       // "qt.glshader.debug=true\n"             // Логи компиляции шейдеров Qt
                       // "qt.qpa.gl.debug=true\n"               // Логи QPA связанные с OpenGL, если нужны
                       // "qt.core.plugin.debug=true\n"          // Логи загрузки плагинов, если нужны
                       // Чтобы уменьшить спам от QPA, но оставить важное:
                       "qt.qpa.critical=true\n"  // Оставляем критические сообщения QPA
                       "qt.qpa.warning=true"     // Оставляем предупреждения QPA
                       // Если qt.qpa.* был нужен для чего-то конкретного, добавьте это правило явно.
                       // "qt.qpa.some.specific.category.debug=true\n"
                       ));

    QApplication app(argc, argv);

    // TODO: Настроить логирование через QLoggingCategory, как указано в правилах (частично сделано выше)

    MainWindow mainWindow;
    mainWindow.show();

    return app.exec();
}