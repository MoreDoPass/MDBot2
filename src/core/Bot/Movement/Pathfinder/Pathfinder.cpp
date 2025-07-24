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

    dtQueryFilter filter;
    filter.setIncludeFlags(0xFFFF);
    filter.setExcludeFlags(0);

    dtPolyRef startRef, endRef;
    navQuery->findNearestPoly(&startPos.x, &m_extents.x, &filter, &startRef, nullptr);
    navQuery->findNearestPoly(&endPos.x, &m_extents.x, &filter, &endRef, nullptr);

    if (!startRef || !endRef)
    {
        qCWarning(pathfinder) << "Не удалось найти полигоны для начальной или конечной точки."
                              << "Start PolyRef:" << startRef << "End PolyRef:" << endRef;
        return {};
    }

    dtPolyRef polys[MAX_POLYS];
    int polyCount = 0;
    navQuery->findPath(startRef, endRef, &startPos.x, &endPos.x, &filter, polys, &polyCount, MAX_POLYS);

    if (polyCount > 0)
    {
        navQuery->findStraightPath(&startPos.x, &endPos.x, polys, polyCount, m_straightPath, m_straightPathFlags,
                                   m_straightPathPolys, &m_straightPathCount, MAX_POLYS);

        std::vector<Vector3> path;
        for (int i = 0; i < m_straightPathCount; ++i)
        {
            path.emplace_back(m_straightPath[i * 3], m_straightPath[i * 3 + 1], m_straightPath[i * 3 + 2]);
        }
        qCInfo(pathfinder) << "Путь успешно найден. Количество точек:" << path.size();
        return path;
    }

    qCWarning(pathfinder) << "Не удалось найти путь между точками.";
    return {};
}
