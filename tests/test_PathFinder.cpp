#include "core/Bot/Movement/PathFinder.h"
#include <QCoreApplication>
#include <QDebug>

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);

    // Путь к mmaps (относительно папки запуска)
    QString mmapsPath = QCoreApplication::applicationDirPath() + "/../../resources/mmaps";
    PathFinder pathFinder;
    if (!pathFinder.init(mmapsPath))
    {
        qCritical() << "Не удалось инициализировать PathFinder!";
        return 1;
    }

    uint32_t mapId = 532;  // Каражан
    if (!pathFinder.loadMapNavMesh(mapId))
    {
        qCritical() << "Не удалось загрузить NavMesh для карты" << mapId;
        return 2;
    }

    // Примерные координаты внутри Каражана (уточните при необходимости)
    float karaStartX = -11185.0f, karaStartY = -1977.0f, karaStartZ = 49.0f;
    float karaEndX = -11180.0f, karaEndY = -1980.0f, karaEndZ = 49.0f;
    std::vector<float> karaPath;
    if (pathFinder.findPath(karaStartX, karaStartY, karaStartZ, karaEndX, karaEndY, karaEndZ, karaPath))
    {
        qInfo() << "[Каражан] Путь построен! Количество точек:" << karaPath.size() / 3;
        for (size_t i = 0; i < karaPath.size(); i += 3)
        {
            qInfo() << "[Каражан] Точка" << (i / 3) << ": X=" << karaPath[i] << "Y=" << karaPath[i + 1]
                    << "Z=" << karaPath[i + 2];
        }
    }
    else
    {
        qWarning() << "[Каражан] Путь не найден!";
    }

    return 0;
}