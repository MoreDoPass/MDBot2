#include "Pathfinder.h"
#include "Logging/Logging.h"
#include <DetourNavMeshQuery.h>
#include <iostream>

Q_LOGGING_CATEGORY(pathfinder, "core.pathfinder")

std::vector<Vector3> Pathfinder::findPath(dtNavMeshQuery* navQuery, const Vector3& startPos, const Vector3& endPos)
{
    if (!navQuery)
    {
        qCWarning(pathfinder) << "Поиск пути невозможен: dtNavMeshQuery не инициализирован.";
        return {};
    }

    // Преобразуем координаты из Z-Up (WoW) в Y-Up (Recast/Detour)
    float recastStartPos[3] = {startPos.x, startPos.z, -startPos.y};
    float recastEndPos[3] = {endPos.x, endPos.z, -endPos.y};

    qCDebug(pathfinder) << "Поиск полигонов. Start WoW:" << startPos.x << startPos.y << startPos.z
                        << "-> Recast:" << recastStartPos[0] << recastStartPos[1] << recastStartPos[2];
    qCDebug(pathfinder) << "End WoW:" << endPos.x << endPos.y << endPos.z << "-> Recast:" << recastEndPos[0]
                        << recastEndPos[1] << recastEndPos[2];
    qCDebug(pathfinder) << "Радиус поиска (extents):" << m_extents.x << m_extents.y << m_extents.z;

    dtQueryFilter filter;
    filter.setIncludeFlags(0xFFFF);
    filter.setExcludeFlags(0);

    dtPolyRef startRef, endRef;
    navQuery->findNearestPoly(recastStartPos, &m_extents.x, &filter, &startRef, nullptr);
    navQuery->findNearestPoly(recastEndPos, &m_extents.x, &filter, &endRef, nullptr);

    if (!startRef || !endRef)
    {
        qCWarning(pathfinder) << "Не удалось найти полигоны для начальной или конечной точки."
                              << "Start PolyRef:" << startRef << "End PolyRef:" << endRef;
        return {};
    }

    dtPolyRef polys[MAX_POLYS];
    int polyCount = 0;
    navQuery->findPath(startRef, endRef, recastStartPos, recastEndPos, &filter, polys, &polyCount, MAX_POLYS);

    if (polyCount > 0)
    {
        navQuery->findStraightPath(recastStartPos, recastEndPos, polys, polyCount, m_straightPath, m_straightPathFlags,
                                   m_straightPathPolys, &m_straightPathCount, MAX_POLYS);

        std::vector<Vector3> path;
        for (int i = 0; i < m_straightPathCount; ++i)
        {
            const float* point = &m_straightPath[i * 3];
            // Преобразуем обратно в Z-Up для использования в игре (x, y, z) -> (x, -z, y)
            path.emplace_back(point[0], -point[2], point[1]);
        }
        qCInfo(pathfinder) << "Путь успешно найден. Количество точек:" << path.size();
        return path;
    }

    qCWarning(pathfinder) << "Не удалось найти путь между точками.";
    return {};
}
