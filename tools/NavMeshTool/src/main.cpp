#include "gui/MainWindow.h"  // Путь к нашему MainWindow
#include <QApplication>
#include <QLoggingCategory>
#include <optional>
// Подключаем MpqManager и NavMeshGenerator
#include "core/MpqManager/MpqManager.h"
#include "core/NavMeshGenerator/NavMeshGenerator.h"  // Убедимся, что NavMeshGenerator.h тоже подключен
#include "core/WoWFiles/Parsers/DBC/DBCParser.h"     // Подключаем наш новый парсер
// Глобальная категория для main или общих логов приложения
Q_LOGGING_CATEGORY(logNavMeshToolApp, "navmesh.app")

int main(int argc, char* argv[])
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
    // --- Интеграция DBCParser для поиска и загрузки карты ---
    qCInfo(logNavMeshToolApp) << "Attempting to find and process 'Black Temple' using DBCParser...";

    // 1. Читаем файл Map.dbc из MPQ-архивов.
    std::vector<char> mapDbcData;  // Сначала объявляем вектор
    // Передаем его по ссылке в readFile. readFile вернет true или false.
    if (!mpqManager.readFile("DBFilesClient\\Map.dbc", reinterpret_cast<std::vector<unsigned char>&>(mapDbcData)))
    {
        qCCritical(logNavMeshToolApp) << "Failed to read Map.dbc. Cannot automatically find and process the map.";
    }
    else
    {
        qCInfo(logNavMeshToolApp) << "Successfully read" << mapDbcData.size() << "bytes from Map.dbc.";

        // 2. Создаем парсер и передаем ему данные.
        const DBCParser dbcParser;
        const std::vector<MapRecord> allMaps = dbcParser.parse(mapDbcData);

        if (allMaps.empty())
        {
            qCCritical(logNavMeshToolApp) << "DBCParser failed to parse map data. Cannot proceed.";
        }
        else
        {
            qCInfo(logNavMeshToolApp) << "Successfully parsed" << allMaps.size() << "maps.";

            // 3. Ищем в списке нужную нам карту.
            const std::string desiredMapName = "Black Temple";
            std::optional<MapRecord> foundMap;

            for (const auto& mapRecord : allMaps)
            {
                // В версии 3.3.5 имя карты "Black Temple", а не "The Black Temple".
                if (mapRecord.displayName == desiredMapName)
                {
                    foundMap = mapRecord;
                    break;  // Нашли, выходим из цикла.
                }
            }

            // 4. Если карта найдена, используем ее для генерации NavMesh.
            if (foundMap.has_value())
            {
                qCInfo(logNavMeshToolApp)
                    << "Found target map!"
                    << "ID:" << foundMap->id << "| Internal Name:" << QString::fromStdString(foundMap->internalName)
                    << "| Display Name:" << QString::fromStdString(foundMap->displayName);

                if (navMeshGenerator.loadMapData(foundMap->internalName, foundMap->id, {}))
                {
                    qCInfo(logNavMeshToolApp)
                        << "Map processing finished for:" << QString::fromStdString(foundMap->displayName)
                        << ". Check output directory.";
                }
                else
                {
                    qCWarning(logNavMeshToolApp)
                        << "Failed to load map data for:" << QString::fromStdString(foundMap->displayName);
                }
            }
            else
            {
                qCWarning(logNavMeshToolApp)
                    << "Map '" << QString::fromStdString(desiredMapName) << "' not found in Map.dbc.";
            }
        }
    }

    MainWindow mainWindow;
    mainWindow.show();

    int result = app.exec();
    qCInfo(logNavMeshToolApp) << "NavMeshTool application finished with code" << result;
    return result;
}