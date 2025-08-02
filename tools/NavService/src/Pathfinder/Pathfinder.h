#pragma once

#include <vector>
#include <string>
#include "../Utils/Vector.h"

// Включаем заголовочные файлы Detour
#include <DetourNavMesh.h>
#include <DetourNavMeshQuery.h>

/**
 * @class Pathfinder
 * @brief Отвечает за поиск пути по заданному NavMesh.
 *
 * Этот класс является утилитой для выполнения запросов поиска пути (A*).
 * Он не хранит состояние и не владеет объектами NavMesh. Ему передаются
 * все необходимые данные для выполнения одного конкретного запроса.
 */
class Pathfinder
{
   public:
    /**
     * @brief Конструктор по умолчанию.
     */
    Pathfinder() = default;

    /**
     * @brief Находит путь между двумя точками, используя предоставленный NavMeshQuery.
     *
     * @param navQuery Указатель на инициализированный объект dtNavMeshQuery.
     * @param startPos Начальная точка пути в мировых координатах.
     * @param endPos Конечная точка пути в мировых координатах.
     * @return std::vector<Vector3> - вектор точек, составляющих путь. Если путь не найден,
     *         вектор будет пустым.
     */
    std::vector<Vector3> findPath(dtNavMeshQuery* navQuery, const Vector3& startPos, const Vector3& endPos);

   private:
    // Максимальное количество полигонов в пути. Определяет размер буфера для поиска.
    static constexpr int MAX_POLYS = 256;

    // Вспомогательные данные для поиска пути, которые могут быть переиспользованы
    // между вызовами для оптимизации, но не хранят специфичное для карты состояние.
    float m_straightPath[MAX_POLYS * 3];
    unsigned char m_straightPathFlags[MAX_POLYS];
    dtPolyRef m_straightPathPolys[MAX_POLYS];
    int m_straightPathCount;

    Vector3 m_extents = {500.0f, 500.0f, 500.0f};  // Область поиска вокруг точки
};
