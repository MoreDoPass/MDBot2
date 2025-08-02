#include "RecastBuilder.h"

#include <QLoggingCategory>
#include <memory>  // Для std::unique_ptr

// Основные заголовки Recast & Detour
#include "Recast.h"
#include "DetourNavMesh.h"
#include "DetourNavMeshBuilder.h"

// Создаем категорию для логирования событий этого класса
Q_LOGGING_CATEGORY(logRecastBuilder, "navmesh.builder.recast")

namespace NavMesh
{
// --- Вспомогательные RAII-обертки для C-style API Recast ---
// Это умные указатели, которые автоматически вызовут нужную функцию
// для освобождения памяти, когда объект выйдет из области видимости.
// Это гарантирует отсутствие утечек памяти, даже если в середине
// функции произойдет ошибка и мы выйдем из нее раньше времени.

struct RecastHeightfieldDeleter
{
    void operator()(rcHeightfield* hf) const
    {
        rcFreeHeightField(hf);
    }
};

struct RecastCompactHeightfieldDeleter
{
    void operator()(rcCompactHeightfield* chf) const
    {
        rcFreeCompactHeightfield(chf);
    }
};

struct RecastContourSetDeleter
{
    void operator()(rcContourSet* cs) const
    {
        rcFreeContourSet(cs);
    }
};

// RecastPolyMeshDeleter и RecastPolyMeshPtr теперь в .h файле

struct RecastPolyMeshDetailDeleter
{
    void operator()(rcPolyMeshDetail* dmesh) const
    {
        rcFreePolyMeshDetail(dmesh);
    }
};

// Определяем типы умных указателей для удобства
using RecastHeightfieldPtr = std::unique_ptr<rcHeightfield, RecastHeightfieldDeleter>;
using RecastCompactHeightfieldPtr = std::unique_ptr<rcCompactHeightfield, RecastCompactHeightfieldDeleter>;
using RecastContourSetPtr = std::unique_ptr<rcContourSet, RecastContourSetDeleter>;
// RecastPolyMeshPtr теперь в .h файле
using RecastPolyMeshDetailPtr = std::unique_ptr<rcPolyMeshDetail, RecastPolyMeshDetailDeleter>;

// Реализация Deleter'а из .h файла
void RecastPolyMeshDeleter::operator()(rcPolyMesh* pmesh) const
{
    rcFreePolyMesh(pmesh);
}

// --- Реализация класса ---

RecastBuilder::RecastBuilder(const rcConfig& config) : m_config(config)
{
    qCDebug(logRecastBuilder) << "RecastBuilder initialized.";
}

std::optional<BuildResult> RecastBuilder::build(const std::vector<float>& vertices, const std::vector<int>& indices,
                                                int tx, int ty)
{
    // Оборачиваем весь процесс в try-catch, чтобы перехватить
    // любые стандартные C++ исключения, если они возникнут.
    // Это не поймает низкоуровневые ошибки доступа к памяти,
    // но является хорошей практикой для отладки.
    try
    {
        // --- 1. ПРОВЕРКА ДАННЫХ ---
        // Эта проверка должна быть в самом начале, до любых операций с векторами.
        if (vertices.empty() || indices.empty())
        {
            qCCritical(logRecastBuilder) << "Input geometry is empty. Aborting build.";
            return std::nullopt;
        }

        // --- 2. ПОДГОТОВКА И ВЫЧИСЛЕНИЕ BBOX ---
        // Вершины уже приходят с правильной системой координат (Y-up).
        // Нам нужно только вычислить их габаритный контейнер (bounding box).
        float bmin[3], bmax[3];
        rcVcopy(bmin, vertices.data());
        rcVcopy(bmax, vertices.data());

        // Начинаем цикл со второй вершины (индекс 3), так как первая уже скопирована.
        for (size_t i = 3; i < vertices.size(); i += 3)
        {
            rcVmin(bmin, &vertices[i]);
            rcVmax(bmax, &vertices[i]);
        }

        // Копируем вычисленный BBox в нашу конфигурацию.
        // Это важно, так как m_config передается по значению в конструктор,
        // но ее нужно дозаполнить перед использованием.
        rcVcopy(m_config.bmin, bmin);
        rcVcopy(m_config.bmax, bmax);

        // Рассчитываем размеры сетки на основе BBox и размера ячейки.
        // Это обязательный шаг перед созданием heightfield.
        rcCalcGridSize(m_config.bmin, m_config.bmax, m_config.cs, &m_config.width, &m_config.height);

        qCInfo(logRecastBuilder) << "Building navmesh for" << (indices.size() / 3) << "triangles.";
        qCDebug(logRecastBuilder) << "Grid size:" << m_config.width << "x" << m_config.height;

        // --- 3. ВОКСЕЛИЗАЦИЯ ---
        rcContext ctx;

        RecastHeightfieldPtr hf(rcAllocHeightfield());
        if (!hf)
        {
            qCCritical(logRecastBuilder) << "rcAllocHeightfield failed.";
            return std::nullopt;
        }

        if (!rcCreateHeightfield(&ctx, *hf, m_config.width, m_config.height, m_config.bmin, m_config.bmax, m_config.cs,
                                 m_config.ch))
        {
            qCCritical(logRecastBuilder) << "rcCreateHeightfield failed.";
            return std::nullopt;
        }

        // "Растеризуем" треугольники: проходим по всем и помечаем воксели, которые они пересекают.
        // Создаем массив флагов для каждого треугольника и помечаем все как проходимые.
        // Передача nullptr здесь недопустима и вызывает крэш.
        const int numTris = static_cast<int>(indices.size() / 3);
        std::vector<unsigned char> triAreas(numTris, RC_WALKABLE_AREA);

        rcRasterizeTriangles(&ctx, vertices.data(), static_cast<int>(vertices.size() / 3), indices.data(),
                             triAreas.data(), numTris, *hf, m_config.walkableClimb);

        // --- 4. ФИЛЬТРАЦИЯ ПРОХОДИМЫХ ПОВЕРХНОСТЕЙ ---
        rcFilterLowHangingWalkableObstacles(&ctx, m_config.walkableClimb, *hf);
        rcFilterLedgeSpans(&ctx, m_config.walkableHeight, m_config.walkableClimb, *hf);
        rcFilterWalkableLowHeightSpans(&ctx, m_config.walkableHeight, *hf);

        // --- 5. ПОСТРОЕНИЕ КОМПАКТНОГО ПОЛЯ ВЫСОТ ---
        RecastCompactHeightfieldPtr chf(rcAllocCompactHeightfield());
        if (!chf)
        {
            qCCritical(logRecastBuilder) << "rcAllocCompactHeightfield failed.";
            return std::nullopt;
        }

        if (!rcBuildCompactHeightfield(&ctx, m_config.walkableHeight, m_config.walkableClimb, *hf, *chf))
        {
            qCCritical(logRecastBuilder) << "rcBuildCompactHeightfield failed.";
            return std::nullopt;
        }

        // --- 6. ПОСТРОЕНИЕ ПОЛЯ РАССТОЯНИЙ И РЕГИОНОВ ---
        // Этот этап - сердце полигонизации.

        // Вычисляем "расстояние" от каждого вокселя до ближайшей стены.
        // Это необходимо для последующего разделения на регионы.
        // Отсутствие этого вызова приводило к крэшу в rcBuildRegions.
        if (!rcBuildDistanceField(&ctx, *chf))
        {
            qCCritical(logRecastBuilder) << "rcBuildDistanceField failed.";
            return std::nullopt;
        }

        // Делим меш на связанные "острова" или регионы. Это нужно для построения
        // правильных контуров на следующем шаге. Мы используем простой и надежный
        // метод "watershed" (водораздел).
        if (!rcBuildRegions(&ctx, *chf, 0, m_config.minRegionArea, m_config.mergeRegionArea))
        {
            qCCritical(logRecastBuilder) << "rcBuildRegions failed.";
            return std::nullopt;
        }

        // Эрозия: "сужаем" проходимую область на радиус агента, чтобы он не терся о стены.
        // Этот шаг должен выполняться ПОСЛЕ построения регионов, чтобы не повредить их.
        if (!rcErodeWalkableArea(&ctx, m_config.walkableRadius, *chf))
        {
            qCCritical(logRecastBuilder) << "rcErodeWalkableArea failed.";
            return std::nullopt;
        }

        // Находим контуры (границы) созданных регионов.
        RecastContourSetPtr cset(rcAllocContourSet());
        if (!cset)
        {
            qCCritical(logRecastBuilder) << "rcAllocContourSet failed.";
            return std::nullopt;
        }
        if (!rcBuildContours(&ctx, *chf, m_config.maxSimplificationError, m_config.maxEdgeLen, *cset))
        {
            qCCritical(logRecastBuilder) << "rcBuildContours failed.";
            return std::nullopt;
        }

        // --- 7. ПОСТРОЕНИЕ ПОЛИГОНАЛЬНОГО МЕША ---
        RecastPolyMeshPtr pmesh(rcAllocPolyMesh());
        if (!pmesh)
        {
            qCCritical(logRecastBuilder) << "rcAllocPolyMesh failed.";
            return std::nullopt;
        }
        if (!rcBuildPolyMesh(&ctx, *cset, m_config.maxVertsPerPoly, *pmesh))
        {
            qCCritical(logRecastBuilder) << "rcBuildPolyMesh failed.";
            return std::nullopt;
        }

        RecastPolyMeshDetailPtr dmesh(rcAllocPolyMeshDetail());
        if (!dmesh)
        {
            qCCritical(logRecastBuilder) << "rcAllocPolyMeshDetail failed.";
            return std::nullopt;
        }
        if (!rcBuildPolyMeshDetail(&ctx, *pmesh, *chf, m_config.detailSampleDist, m_config.detailSampleMaxError,
                                   *dmesh))
        {
            qCCritical(logRecastBuilder) << "rcBuildPolyMeshDetail failed.";
            return std::nullopt;
        }

        // --- 8. УПАКОВКА ДАННЫХ ДЛЯ DETOUR ---
        if (m_config.maxVertsPerPoly == 0)
        {
            qCCritical(logRecastBuilder) << "maxVertsPerPoly must be > 0.";
            return std::nullopt;
        }

        dtNavMeshCreateParams params;
        memset(&params, 0, sizeof(params));
        params.verts = pmesh->verts;
        params.vertCount = pmesh->nverts;
        params.polys = pmesh->polys;
        params.polyAreas = pmesh->areas;
        params.polyFlags = pmesh->flags;
        params.polyCount = pmesh->npolys;
        params.nvp = pmesh->nvp;
        params.detailMeshes = dmesh->meshes;
        params.detailVerts = dmesh->verts;
        params.detailVertsCount = dmesh->nverts;
        params.detailTris = dmesh->tris;
        params.detailTriCount = dmesh->ntris;
        params.offMeshConCount = 0;
        params.walkableHeight = (float)m_config.walkableHeight * m_config.ch;
        params.walkableRadius = (float)m_config.walkableRadius * m_config.cs;
        params.walkableClimb = (float)m_config.walkableClimb * m_config.ch;
        rcVcopy(params.bmin, pmesh->bmin);
        rcVcopy(params.bmax, pmesh->bmax);
        params.cs = m_config.cs;
        params.ch = m_config.ch;
        params.buildBvTree = true;
        // Устанавливаем координаты тайла, которые будут записаны в заголовок
        params.tileX = tx;
        params.tileY = ty;

        qCDebug(logRecastBuilder) << "Preparing to create Detour data. Polygons:" << pmesh->npolys
                                  << "Vertices:" << pmesh->nverts;

        unsigned char* navData = nullptr;
        int navDataSize = 0;

        if (!dtCreateNavMeshData(&params, &navData, &navDataSize))
        {
            qCCritical(logRecastBuilder) << "dtCreateNavMeshData failed.";
            return std::nullopt;
        }

        qCInfo(logRecastBuilder) << "NavMesh successfully built! Size:" << navDataSize << "bytes.";

        BuildResult result;
        result.navmeshData.assign(navData, navData + navDataSize);
        dtFree(navData);

        // Перемещаем владение pmesh в нашу структуру.
        // Все остальные умные указатели (hf, chf, cset, dmesh) уничтожатся
        // автоматически при выходе из функции благодаря RAII.
        result.polyMesh = std::move(pmesh);

        return result;
    }
    catch (const std::exception& e)
    {
        qCCritical(logRecastBuilder) << "A C++ exception was caught during NavMesh generation:" << e.what();
        return std::nullopt;
    }
    catch (...)
    {
        qCCritical(logRecastBuilder) << "An unknown exception was caught during NavMesh generation.";
        return std::nullopt;
    }
}

}  // namespace NavMesh