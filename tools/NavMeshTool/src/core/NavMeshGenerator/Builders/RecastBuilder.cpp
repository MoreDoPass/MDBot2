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

struct RecastPolyMeshDeleter
{
    void operator()(rcPolyMesh* pmesh) const
    {
        rcFreePolyMesh(pmesh);
    }
};

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
using RecastPolyMeshPtr = std::unique_ptr<rcPolyMesh, RecastPolyMeshDeleter>;
using RecastPolyMeshDetailPtr = std::unique_ptr<rcPolyMeshDetail, RecastPolyMeshDetailDeleter>;

// --- Реализация класса ---

RecastBuilder::RecastBuilder(const rcConfig& config) : m_config(config)
{
    qCDebug(logRecastBuilder) << "RecastBuilder initialized.";
}

std::optional<std::vector<unsigned char>> RecastBuilder::build(const std::vector<float>& vertices,
                                                               const std::vector<int>& indices)
{
    // --- 1. ПРОВЕРКА И ПОДГОТОВКА ДАННЫХ ---

    if (vertices.empty() || indices.empty())
    {
        qCCritical(logRecastBuilder) << "Input geometry is empty. Aborting build.";
        return std::nullopt;
    }

    // --- 1a. Конвертация осей и вычисление BBox ---
    // Recast ожидает Y-up, а WoW использует Z-up.
    // Мы конвертируем (x, y, z) -> (x, z, -y)
    // Также находим габариты мира (bounding box) для rcConfig.

    std::vector<float> recastVertices = vertices;  // Копируем, чтобы изменить на месте
    float bmin[3] = {vertices[0], vertices[2], -vertices[1]};
    float bmax[3] = {vertices[0], vertices[2], -vertices[1]};

    for (size_t i = 0; i < recastVertices.size(); i += 3)
    {
        const float y = recastVertices[i + 1];
        const float z = recastVertices[i + 2];
        recastVertices[i + 1] = z;   // new_y = z
        recastVertices[i + 2] = -y;  // new_z = -y

        // Обновляем BBox
        const float* v = &recastVertices[i];
        rcVmin(bmin, v);
        rcVmax(bmax, v);
    }

    // Копируем вычисленный BBox в нашу конфигурацию
    rcVcopy(m_config.bmin, bmin);
    rcVcopy(m_config.bmax, bmax);

    // Рассчитываем размеры сетки на основе BBox и размера ячейки.
    // Это обязательный шаг перед созданием heightfield.
    rcCalcGridSize(m_config.bmin, m_config.bmax, m_config.cs, &m_config.width, &m_config.height);

    qCInfo(logRecastBuilder) << "Building navmesh for" << (indices.size() / 3) << "triangles.";
    qCDebug(logRecastBuilder) << "Grid size:" << m_config.width << "x" << m_config.height;

    // --- 2. ВОКСЕЛИЗАЦИЯ ---
    // На этом этапе мы превращаем нашу "векторную" геометрию (треугольники)
    // в "растровую" (воксели / 3D-пиксели).

    // Создаем контекст для логирования ошибок от Recast
    rcContext ctx;

    // Создаем heightfield - основную структуру данных для вокселизации.
    RecastHeightfieldPtr hf(rcAllocHeightfield());
    if (!hf)
    {
        qCCritical(logRecastBuilder) << "rcAllocHeightfield failed.";
        return std::nullopt;
    }

    // Инициализируем созданный heightfield с нашими параметрами.
    if (!rcCreateHeightfield(&ctx, *hf, m_config.width, m_config.height, m_config.bmin, m_config.bmax, m_config.cs,
                             m_config.ch))
    {
        qCCritical(logRecastBuilder) << "rcCreateHeightfield failed.";
        return std::nullopt;
    }

    // "Растеризуем" треугольники: проходим по всем и помечаем воксели, которые они пересекают.
    // Создаем временный массив для флагов треугольников (пока без зон).
    std::vector<unsigned char> triAreas(indices.size() / 3, 0);
    rcRasterizeTriangles(&ctx, recastVertices.data(), static_cast<int>(recastVertices.size() / 3), indices.data(),
                         triAreas.data(), static_cast<int>(indices.size() / 3), *hf, m_config.walkableClimb);

    // --- 3. ФИЛЬТРАЦИЯ ПРОХОДИМЫХ ПОВЕРХНОСТЕЙ ---
    // После растеризации у нас есть "сырая" карта высот. Теперь мы применяем
    // серию фильтров, чтобы убрать места, где агент не должен ходить, даже
    // если они плоские.

    // Убираем "потолки" (поверхности, под которыми не поместится агент).
    rcFilterLowHangingWalkableObstacles(&ctx, m_config.walkableClimb, *hf);
    // Убираем уступы, с которых нельзя спрыгнуть, но на которые можно было бы залезть снизу.
    rcFilterLedgeSpans(&ctx, m_config.walkableHeight, m_config.walkableClimb, *hf);
    // Убираем небольшие островки/участки, на которые нельзя залезть.
    rcFilterWalkableLowHeightSpans(&ctx, m_config.walkableHeight, *hf);

    // --- 4. ПОСТРОЕНИЕ КОМПАКТНОГО ПОЛЯ ВЫСОТ ---
    // Этот шаг "уплотняет" данные из heightfield'а в более эффективную структуру,
    // готовя их к этапу деления на регионы и построению полигонов.
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

    // --- 5. ПОСТРОЕНИЕ РЕГИОНОВ И КОНТУРОВ ---
    // Этот этап - сердце полигонизации.

    // Эрозия: "сужаем" проходимую область на радиус агента, чтобы он не терся о стены.
    if (!rcErodeWalkableArea(&ctx, m_config.walkableRadius, *chf))
    {
        qCCritical(logRecastBuilder) << "rcErodeWalkableArea failed.";
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

    // --- 6. ПОСТРОЕНИЕ ПОЛИГОНАЛЬНОГО МЕША ---
    // Теперь мы, наконец, строим из контуров сам полигональный меш.
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

    // (Опционально, но рекомендуется) Строим детализированный меш для более
    // точного следования по пути.
    RecastPolyMeshDetailPtr dmesh(rcAllocPolyMeshDetail());
    if (!dmesh)
    {
        qCCritical(logRecastBuilder) << "rcAllocPolyMeshDetail failed.";
        return std::nullopt;
    }
    if (!rcBuildPolyMeshDetail(&ctx, *pmesh, *chf, m_config.detailSampleDist, m_config.detailSampleMaxError, *dmesh))
    {
        qCCritical(logRecastBuilder) << "rcBuildPolyMeshDetail failed.";
        return std::nullopt;
    }

    // --- 7. УПАКОВКА ДАННЫХ ДЛЯ DETOUR ---
    // На этом этапе Recast свою работу закончил. Мы берем построенные им
    // меши и упаковываем их в формат, понятный для Detour.

    // Убираем из конфигурации лишние данные, не относящиеся к Detour.
    // Это не обязательно, но рекомендуется документацией.
    m_config.walkableRadius = 0;

    // Если указано максимальное количество вершин на полигон, Detour это учтет.
    if (m_config.maxVertsPerPoly == 0)
    {
        qCCritical(logRecastBuilder) << "maxVertsPerPoly must be > 0.";
        return std::nullopt;
    }

    dtNavMeshCreateParams params;
    memset(&params, 0, sizeof(params));  // Обнуляем структуру
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
    params.offMeshConCount = 0;  // Пока не используем Off-Mesh соединения
    params.walkableHeight = (float)m_config.walkableHeight * m_config.ch;
    params.walkableRadius = (float)m_config.walkableRadius * m_config.cs;
    params.walkableClimb = (float)m_config.walkableClimb * m_config.ch;
    rcVcopy(params.bmin, pmesh->bmin);
    rcVcopy(params.bmax, pmesh->bmax);
    params.cs = m_config.cs;
    params.ch = m_config.ch;
    params.buildBvTree = true;  // Важно для производительности поиска пути

    qCDebug(logRecastBuilder) << "Preparing to create Detour data. Polygons:" << pmesh->npolys
                              << "Vertices:" << pmesh->nverts;

    unsigned char* navData = nullptr;
    int navDataSize = 0;

    // Главная функция Detour, создающая финальный байтовый массив.
    if (!dtCreateNavMeshData(&params, &navData, &navDataSize))
    {
        qCCritical(logRecastBuilder) << "dtCreateNavMeshData failed.";
        return std::nullopt;
    }

    qCInfo(logRecastBuilder) << "NavMesh successfully built! Size:" << navDataSize << "bytes.";

    // --- 8. ФИНАЛИЗАЦИЯ ---
    // Копируем данные из C-массива в C++ вектор и освобождаем память.
    std::vector<unsigned char> result(navData, navData + navDataSize);

    // dtCreateNavMeshData использует свой собственный аллокатор.
    // Память нужно освобождать через dtFree.
    dtFree(navData);

    return result;
}

}  // namespace NavMesh