#include "gui/MainWindow.h"  // Путь к нашему MainWindow
#include <QApplication>
#include <QLoggingCategory>

// Подключаем MpqManager и NavMeshGenerator
#include "core/MpqManager/MpqManager.h"
#include "core/NavMeshGenerator/NavMeshGenerator.h"  // Убедимся, что NavMeshGenerator.h тоже подключен

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

    // Создаем и инициализируем MpqManager
    MpqManager mpqManager;
    // Путь к корневой директории WoW Sirus (без /Data)
    std::string wowSirusPath =
        "C:/Games/WoW Sirus/World of Warcraft Sirus";  // Используем прямой слеш для совместимости
    bool mpqLoaded = mpqManager.openSirusInstallation(wowSirusPath);
    if (!mpqLoaded)
    {
        qCCritical(logNavMeshToolApp) << "Failed to load MPQ archives from " << QString::fromStdString(wowSirusPath)
                                      << ". NavMesh generation might not work correctly.";
        // Можно здесь завершить приложение или продолжить с ограниченной функциональностью
        // return 1; // Пример завершения с ошибкой
    }
    else
    {
        qCInfo(logNavMeshToolApp) << "MPQ archives loaded successfully from " << QString::fromStdString(wowSirusPath)
                                  << ".";
    }

    // Создаем NavMeshGenerator, передавая ему ссылку на mpqManager
    NavMesh::NavMeshGenerator navMeshGenerator(mpqManager);

    // Пытаемся загрузить данные для конкретной карты
    // Пока что adtCoords не используются, передаем пустой вектор
    std::string mapNameToLoad = "BlackTemple";
    if (navMeshGenerator.loadMapData(mapNameToLoad, {}))
    {
        qCInfo(logNavMeshToolApp) << "Successfully initiated loading for map:" << QString::fromStdString(mapNameToLoad);

        std::string objFilePath = mapNameToLoad + ".obj";
        qCInfo(logNavMeshToolApp) << "Сохраняем геометрию в" << QString::fromStdString(objFilePath) << "...";
        if (navMeshGenerator.saveToObj(objFilePath))
        {
            qCInfo(logNavMeshToolApp) << "Геометрия успешно сохранена в .obj файл.";
        }
        else
        {
            qCWarning(logNavMeshToolApp) << "Не удалось сохранить .obj файл.";
        }

        // Главное действие: строим и сохраняем NavMesh.
        // Файл будет сохранен в папку, откуда запускается приложение (обычно папка сборки).
        std::string navMeshFilePath = mapNameToLoad + ".mmap";
        qCInfo(logNavMeshToolApp) << "Начинаем построение NavMesh. Результат будет в"
                                  << QString::fromStdString(navMeshFilePath) << "...";
        if (navMeshGenerator.buildAndSaveNavMesh(navMeshFilePath))
        {
            qCInfo(logNavMeshToolApp) << "NavMesh успешно построен и сохранен.";
        }
        else
        {
            qCCritical(logNavMeshToolApp) << "КРИТИЧЕСКАЯ ОШИБКА при построении NavMesh!";
        }
    }
    else
    {
        qCWarning(logNavMeshToolApp) << "Failed to load map data for:" << QString::fromStdString(mapNameToLoad);
    }

    MainWindow mainWindow;
    mainWindow.show();

    int result = app.exec();
    qCInfo(logNavMeshToolApp) << "NavMeshTool application finished with code" << result;
    return result;
}