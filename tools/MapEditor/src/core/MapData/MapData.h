#ifndef MAPDATA_H
#define MAPDATA_H

#include "Waypoint.h"  // Включаем определение Waypoint
#include <QList>
#include <QString>
#include <QJsonObject>  // Required for fromJsonObject and toJsonObject
#include <QJsonArray>   // Для преобразования QSet в/из QJsonArray

// Структура для простого AABB препятствия
struct Obstacle
{
    // QList<QVector3D> vertices; // Вершины, определяющие основание полигона
    // float height;            // Высота выдавливания полигона
    // Для обратной совместимости и постепенного перехода, пока оставим и старые поля,
    // но будем ориентироваться на новые. Возможно, стоит ввести тип препятствия.

    QVector3D minCorner;  // Используется для AABB, пока оставим для LoS
    QVector3D maxCorner;  // Используется для AABB, пока оставим для LoS

    // Старые поля для призматических препятствий
    QList<QVector3D> baseVertices;  // Вершины основания полигона (на плоскости Y=0)
    float obstacleHeight = 5.0f;    // Высота препятствия по умолчанию

    // Новое поле для произвольных 3D форм
    QList<QVector3D> shapeVertices;  // Вершины, определяющие полную 3D геометрию

    int id = 0;
    QString name;

    // Конструктор по умолчанию (может понадобиться для QList или других контейнеров)
    Obstacle() = default;

    // Конструктор для AABB (старый, может пригодиться для тестов или простых блоков)
    Obstacle(QVector3D min, QVector3D max, int p_id = 0, QString p_name = "")
        : minCorner(min), maxCorner(max), id(p_id), name(std::move(p_name))
    {
        // Если baseVertices пуст, а min/max заданы, можно попробовать создать baseVertices для прямоугольника
        if (baseVertices.isEmpty() && (!min.isNull() || !max.isNull()))
        {
            baseVertices.append(QVector3D(min.x(), 0.0f, min.z()));
            baseVertices.append(QVector3D(max.x(), 0.0f, min.z()));
            baseVertices.append(QVector3D(max.x(), 0.0f, max.z()));
            baseVertices.append(QVector3D(min.x(), 0.0f, max.z()));
            obstacleHeight = max.y() - min.y();
        }
    }

    // Конструктор для полигональных призматических препятствий
    Obstacle(QList<QVector3D> p_baseVertices, float p_height, int p_id = 0, QString p_name = "")
        : baseVertices(std::move(p_baseVertices)), obstacleHeight(p_height), id(p_id), name(std::move(p_name))
    {
        // Рассчитать minCorner/maxCorner для AABB, охватывающего полигональное препятствие
        if (!this->baseVertices.isEmpty())
        {
            float minX = this->baseVertices[0].x(), maxX = this->baseVertices[0].x();
            // float minY = 0.0f, maxY = p_height; // Y координата основания 0, верх p_height
            float minZ = this->baseVertices[0].z(), maxZ = this->baseVertices[0].z();
            for (const QVector3D& v : this->baseVertices)
            {
                if (v.x() < minX) minX = v.x();
                if (v.x() > maxX) maxX = v.x();
                if (v.z() < minZ) minZ = v.z();
                if (v.z() > maxZ) maxZ = v.z();
            }
            minCorner = QVector3D(minX, 0.0f, minZ);  // Основание на Y=0
            maxCorner = QVector3D(maxX, p_height, maxZ);
        }
    }

    // НОВЫЙ конструктор для произвольных 3D форм
    Obstacle(QList<QVector3D> p_shapeVertices, int p_id = 0, QString p_name = "")
        : shapeVertices(std::move(p_shapeVertices)), id(p_id), name(std::move(p_name))
    {
        // Рассчитать minCorner/maxCorner для AABB, охватывающего все shapeVertices
        if (!this->shapeVertices.isEmpty())
        {
            minCorner = this->shapeVertices[0];
            maxCorner = this->shapeVertices[0];
            for (const QVector3D& v : this->shapeVertices)
            {
                minCorner.setX(qMin(minCorner.x(), v.x()));
                minCorner.setY(qMin(minCorner.y(), v.y()));
                minCorner.setZ(qMin(minCorner.z(), v.z()));
                maxCorner.setX(qMax(maxCorner.x(), v.x()));
                maxCorner.setY(qMax(maxCorner.y(), v.y()));
                maxCorner.setZ(qMax(maxCorner.z(), v.z()));
            }
            // baseVertices и obstacleHeight остаются неинициализированными или нулевыми для этого типа
            this->baseVertices.clear();
            this->obstacleHeight = 0.0f;
        }
    }

    // Проверка, находится ли точка внутри AABB (включая границы)
    bool contains(const QVector3D& point) const
    {
        return point.x() >= minCorner.x() && point.x() <= maxCorner.x() && point.y() >= minCorner.y() &&
               point.y() <= maxCorner.y() && point.z() >= minCorner.z() && point.z() <= maxCorner.z();
    }
};

class MapData
{
   public:
    int mapId = 0;
    QString mapName;
    QString version;
    QList<Waypoint> waypoints;
    QList<Obstacle> obstacles;  // <--- Добавлено: список препятствий

    MapData() = default;

    // Опционально: конструктор для удобства
    MapData(int p_mapId, QString p_mapName, QString p_version)
        : mapId(p_mapId), mapName(std::move(p_mapName)), version(std::move(p_version))
    {
    }

    // Методы для управления вейпоинтами (примеры)
    void addWaypoint(const Waypoint& waypoint)
    {
        waypoints.append(waypoint);
    }

    const Waypoint* findWaypointById(int waypointId) const
    {
        for (const auto& wp : waypoints)
        {
            if (wp.id == waypointId)
            {
                return &wp;
            }
        }
        return nullptr;
    }

    Waypoint* findWaypointById(int waypointId)
    {
        for (auto& wp : waypoints)
        {
            if (wp.id == waypointId)
            {
                return &wp;
            }
        }
        return nullptr;
    }

    bool removeWaypointById(int waypointId)
    {
        for (int i = 0; i < waypoints.size(); ++i)
        {
            if (waypoints[i].id == waypointId)
            {
                waypoints.removeAt(i);
                return true;
            }
        }
        return false;
    }

    void clear()
    {
        mapId = 0;
        mapName.clear();
        version.clear();
        waypoints.clear();
        obstacles.clear();  // <--- Очистка препятствий
    }
};

#endif  // MAPDATA_H