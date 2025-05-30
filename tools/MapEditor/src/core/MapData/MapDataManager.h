#ifndef MAPDATAMANAGER_H
#define MAPDATAMANAGER_H

#include "MapData.h"
#include <QString>
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(mapDataManagerLog)

class MapDataManager
{
   public:
    MapDataManager();

    bool loadMapData(const QString& filePath, MapData& outMapData);
    bool saveMapData(const QString& filePath, const MapData& mapData);  // Декларация для полноты, реализация позже

   private:
    // Вспомогательные функции могут быть здесь, если понадобятся
};

#endif  // MAPDATAMANAGER_H