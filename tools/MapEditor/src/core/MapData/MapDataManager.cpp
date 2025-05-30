#include "MapDataManager.h"
#include "Waypoint.h"  // MapData его уже включает, но для ясности можно и тут
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>  // Для qCInfo, qCWarning

Q_LOGGING_CATEGORY(mapDataManagerLog, "mapeditor.mapdatamanager")

MapDataManager::MapDataManager()
{
    // Конструктор может быть пустым или инициализировать что-либо
}

bool MapDataManager::loadMapData(const QString& filePath, MapData& outMapData)
{
    outMapData.clear();  // Очищаем данные перед загрузкой новых

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qCWarning(mapDataManagerLog) << "Failed to open file:" << filePath << file.errorString();
        return false;
    }

    QByteArray jsonData = file.readAll();
    file.close();

    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData, &parseError);

    if (parseError.error != QJsonParseError::NoError)
    {
        qCWarning(mapDataManagerLog) << "Failed to parse JSON from file:" << filePath << parseError.errorString();
        return false;
    }

    if (!jsonDoc.isObject())
    {
        qCWarning(mapDataManagerLog) << "JSON document is not an object:" << filePath;
        return false;
    }

    QJsonObject rootObject = jsonDoc.object();

    outMapData.mapId = rootObject.value("map_id").toInt(0);
    outMapData.mapName = rootObject.value("map_name").toString();
    outMapData.version = rootObject.value("version").toString();

    if (rootObject.contains("waypoints") && rootObject.value("waypoints").isArray())
    {
        QJsonArray waypointsArray = rootObject.value("waypoints").toArray();
        for (const QJsonValue& wpValue : waypointsArray)
        {
            if (wpValue.isObject())
            {
                Waypoint wp = Waypoint::fromJsonObject(wpValue.toObject());
                outMapData.addWaypoint(wp);
            }
            else
            {
                qCWarning(mapDataManagerLog) << "Waypoint entry is not an object in file:" << filePath;
            }
        }
    }
    else
    {
        qCWarning(mapDataManagerLog) << "'waypoints' array not found or not an array in file:" << filePath;
        // Это может быть не критичной ошибкой, если файл просто не содержит вейпоинтов
    }

    qCInfo(mapDataManagerLog) << "Successfully loaded map data from" << filePath << "- MapID:" << outMapData.mapId
                              << "Name:" << outMapData.mapName << "Version:" << outMapData.version
                              << "Waypoints loaded:" << outMapData.waypoints.size();
    return true;
}

bool MapDataManager::saveMapData(const QString& filePath, const MapData& mapData)
{
    QJsonObject rootObject;
    rootObject["map_id"] = mapData.mapId;
    rootObject["map_name"] = mapData.mapName;
    rootObject["version"] = mapData.version;

    QJsonArray waypointsArray;
    for (const Waypoint& wp : mapData.waypoints)
    {
        waypointsArray.append(wp.toJsonObject());
    }
    rootObject["waypoints"] = waypointsArray;

    QJsonDocument jsonDoc(rootObject);
    QByteArray jsonData = jsonDoc.toJson(QJsonDocument::Indented);  // Indented для читаемости

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        qCWarning(mapDataManagerLog) << "Failed to open file for writing:" << filePath << file.errorString();
        return false;
    }

    if (file.write(jsonData) == -1)
    {
        qCWarning(mapDataManagerLog) << "Failed to write data to file:" << filePath << file.errorString();
        file.close();
        return false;
    }

    file.close();
    qCInfo(mapDataManagerLog) << "Successfully saved map data to" << filePath
                              << "Waypoints saved:" << mapData.waypoints.size();
    return true;
}