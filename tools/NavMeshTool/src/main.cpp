#include "gui/MainWindow.h"  // Путь к нашему MainWindow
#include <QApplication>
#include <QLoggingCategory>

// Глобальная категория для main или общих логов приложения
Q_LOGGING_CATEGORY(logNavMeshToolApp, "navmesh.app")

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    // Настройка правил фильтрации логов (можно вынести в отдельную функцию или класс)
    // Показываем все сообщения из наших категорий и предупреждения/ошибки от Qt
    QLoggingCategory::setFilterRules(
        "navmesh.*.debug=true\n"  // Все сообщения из пространства имен navmesh
        "qt.core.logging.debug=false\n"
        "qt.gui.logging.debug=false\n"  // Отключаем излишние debug-сообщения от Qt
        // "*.info=true" // Можно включить все info сообщения если нужно
    );

    qCInfo(logNavMeshToolApp) << "NavMeshTool application starting...";

    MainWindow mainWindow;
    mainWindow.show();

    int result = app.exec();
    qCInfo(logNavMeshToolApp) << "NavMeshTool application finished with code" << result;
    return result;
}