#ifndef WAYPOINT_H
#define WAYPOINT_H

#include <QString>
#include <QVector3D>
#include <QSet>         // Используем QSet
#include <QJsonObject>  // Required for fromJsonObject and toJsonObject
#include <QJsonArray>   // Для преобразования QSet в/из QJsonArray

struct Waypoint
{
    int id = 0;
    QString name;
    QVector3D coordinates;
    QSet<int> connectedWaypointIds;  // Используем это поле

    Waypoint() = default;
    // Обновленный конструктор
    Waypoint(int p_id, QString p_name, QVector3D p_coordinates, const QSet<int>& p_connectedWaypointIds = {})
        : id(p_id), name(std::move(p_name)), coordinates(p_coordinates), connectedWaypointIds(p_connectedWaypointIds)
    {
    }

    static Waypoint fromJsonObject(const QJsonObject& jsonObject);
    QJsonObject toJsonObject() const;

    // Обновленный оператор сравнения
    bool operator==(const Waypoint& other) const
    {
        return id == other.id && name == other.name && coordinates == other.coordinates &&
               connectedWaypointIds == other.connectedWaypointIds;  // Только новое поле
    }
};

#endif  // WAYPOINT_H