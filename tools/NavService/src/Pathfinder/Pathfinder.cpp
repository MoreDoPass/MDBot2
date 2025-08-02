#include "Pathfinder.h"
#include "../Utils/Logger.h"
#include "../Utils/CoordinateConverter.h"
#include <iostream>

std::vector<Vector3> Pathfinder::findPath(dtNavMeshQuery* navQuery, const Vector3& startPos, const Vector3& endPos)
{
    if (!navQuery)
    {
        qCWarning(pathfinder) << "Поиск пути невозможен: dtNavMeshQuery не инициализирован.";
        return {};
    }

    // Преобразуем координаты из WoW в Recast используя наш CoordinateConverter
    Vector3 recastStartPos = CoordinateConverter::wowToRecast(startPos);
    Vector3 recastEndPos = CoordinateConverter::wowToRecast(endPos);

    qCDebug(pathfinder) << "Поиск полигонов. Start WoW:"
                        << QString("(%1, %2, %3)").arg(startPos.x).arg(startPos.y).arg(startPos.z) << "-> Recast:"
                        << QString("(%1, %2, %3)").arg(recastStartPos.x).arg(recastStartPos.y).arg(recastStartPos.z);
    qCDebug(pathfinder) << "End WoW:" << QString("(%1, %2, %3)").arg(endPos.x).arg(endPos.y).arg(endPos.z)
                        << "-> Recast:"
                        << QString("(%1, %2, %3)").arg(recastEndPos.x).arg(recastEndPos.y).arg(recastEndPos.z);
    qCDebug(pathfinder) << "Радиус поиска (extents):"
                        << QString("(%1, %2, %3)").arg(m_extents.x).arg(m_extents.y).arg(m_extents.z);

    dtQueryFilter filter;
    filter.setIncludeFlags(0xFFFF);
    filter.setExcludeFlags(0);

    dtPolyRef startRef, endRef;
    float startPosArray[3] = {recastStartPos.x, recastStartPos.y, recastStartPos.z};
    float endPosArray[3] = {recastEndPos.x, recastEndPos.y, recastEndPos.z};
    float extentsArray[3] = {m_extents.x, m_extents.y, m_extents.z};

    navQuery->findNearestPoly(startPosArray, extentsArray, &filter, &startRef, nullptr);
    navQuery->findNearestPoly(endPosArray, extentsArray, &filter, &endRef, nullptr);

    if (!startRef || !endRef)
    {
        qCWarning(pathfinder) << "Не удалось найти полигоны для начальной или конечной точки."
                              << "Start PolyRef:" << startRef << "End PolyRef:" << endRef;
        return {};
    }

    dtPolyRef polys[MAX_POLYS];
    int polyCount = 0;
    navQuery->findPath(startRef, endRef, startPosArray, endPosArray, &filter, polys, &polyCount, MAX_POLYS);

    if (polyCount > 0)
    {
        navQuery->findStraightPath(startPosArray, endPosArray, polys, polyCount, m_straightPath, m_straightPathFlags,
                                   m_straightPathPolys, &m_straightPathCount, MAX_POLYS);

        std::vector<Vector3> path;
        for (int i = 0; i < m_straightPathCount; ++i)
        {
            const float* point = &m_straightPath[i * 3];
            // Преобразуем обратно из Recast в WoW координаты
            Vector3 recastPoint(point[0], point[1], point[2]);
            Vector3 wowPoint = CoordinateConverter::recastToWow(recastPoint);
            path.emplace_back(wowPoint);
        }
        qCInfo(pathfinder) << "Путь успешно найден. Количество точек:" << path.size();
        return path;
    }

    qCWarning(pathfinder) << "Не удалось найти путь между точками.";
    return {};
}
