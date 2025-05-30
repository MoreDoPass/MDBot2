#include "Waypoint.h"
#include <QJsonArray>
#include <QJsonValue>
#include <QLoggingCategory>

// Объявим категорию логирования, если она будет использоваться здесь
// Q_LOGGING_CATEGORY(waypointLog, "mapeditor.waypoint")

Waypoint Waypoint::fromJsonObject(const QJsonObject& jsonObject)
{
    Waypoint wp;
    wp.id = jsonObject.value("id").toInt(0);  // По умолчанию 0, если ключ отсутствует или не число
    wp.name = jsonObject.value("name").toString();

    if (jsonObject.contains("coordinates") && jsonObject.value("coordinates").isObject())
    {
        QJsonObject coordsObj = jsonObject.value("coordinates").toObject();
        wp.coordinates.setX(coordsObj.value("x").toDouble(0.0));
        wp.coordinates.setY(coordsObj.value("y").toDouble(0.0));
        wp.coordinates.setZ(coordsObj.value("z").toDouble(0.0));
    }
    // else
    // {
    // qCWarning(waypointLog) << "Waypoint ID" << wp.id << "missing or invalid 'coordinates' object.";
    // }

    // Используем ключ "connections" для совместимости, но читаем в QSet
    if (jsonObject.contains("connections") && jsonObject.value("connections").isArray())
    {
        QJsonArray connectionsArray = jsonObject.value("connections").toArray();
        for (const QJsonValue& val : connectionsArray)
        {
            if (val.isDouble() || val.isString())  // ID могут быть числами или строками чисел
            {
                wp.connectedWaypointIds.insert(val.toInt());
            }
        }
    }
    // else
    // {
    // qCWarning(waypointLog) << "Waypoint ID" << wp.id << "missing or invalid 'connections' array.";
    // }
    return wp;
}

QJsonObject Waypoint::toJsonObject() const
{
    QJsonObject jsonObject;
    jsonObject["id"] = id;
    jsonObject["name"] = name;

    QJsonObject coordsObj;
    coordsObj["x"] = coordinates.x();
    coordsObj["y"] = coordinates.y();
    coordsObj["z"] = coordinates.z();
    jsonObject["coordinates"] = coordsObj;

    QJsonArray connectionsArray;
    // Преобразуем QSet в QJsonArray
    for (int connId : connectedWaypointIds)  // Итерируем по QSet
    {
        connectionsArray.append(connId);
    }
    // Используем ключ "connections" для совместимости
    jsonObject["connections"] = connectionsArray;

    return jsonObject;
}