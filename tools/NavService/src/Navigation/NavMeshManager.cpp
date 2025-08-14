#include "NavMeshManager.h"
#include "Utils/Logger.h"
#include "Utils/CoordinateConverter.h"
#include <DetourNavMeshBuilder.h>
#include <fstream>
#include <algorithm>
#include <cstring>  // Для memcpy

NavMeshManager::NavMeshManager(const std::string& navMeshBasePath) : m_navMeshBasePath(navMeshBasePath)
{
    qCInfo(navMeshLog) << "NavMeshManager created. NavMesh path:" << QString::fromStdString(m_navMeshBasePath);
}

NavMeshManager::~NavMeshManager()
{
    qCInfo(navMeshLog) << "NavMeshManager destroyed. All meshes freed automatically.";
}

dtNavMesh* NavMeshManager::getNavMeshForMap(uint32_t mapId)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_navMeshes.find(mapId);
    if (it != m_navMeshes.end())
    {
        return it->second->navMesh.get();
    }

    NavMeshData* data = initNavMesh(mapId);
    if (!data)
    {
        qCCritical(navMeshLog) << "Failed to initialize NavMesh for map" << mapId;
        return nullptr;
    }
    return data->navMesh.get();
}

void NavMeshManager::ensureTilesLoaded(uint32_t mapId, const Vector3& start, const Vector3& end)
{
    dtNavMesh* navMesh = getNavMeshForMap(mapId);
    if (!navMesh)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    NavMeshData* data = m_navMeshes.at(mapId).get();

    Vector3 recastStart = CoordinateConverter::wowToRecast(start);
    Vector3 recastEnd = CoordinateConverter::wowToRecast(end);

    int startTx, startTy, endTx, endTy;
    navMesh->calcTileLoc(&recastStart.x, &startTx, &startTy);
    navMesh->calcTileLoc(&recastEnd.x, &endTx, &endTy);

    int minTx = std::min(startTx, endTx);
    int maxTx = std::max(startTx, endTx);
    int minTy = std::min(startTy, endTy);
    int maxTy = std::max(startTy, endTy);

    qCDebug(navMeshLog) << "Ensuring tiles are loaded for map" << mapId << "in rect: (" << minTx << "," << minTy
                        << ") to (" << maxTx << "," << maxTy << ")";

    for (int y = minTy; y <= maxTy; ++y)
    {
        for (int x = minTx; x <= maxTx; ++x)
        {
            loadTilesInArea(mapId, data, x, y);
        }
    }
}

NavMeshManager::NavMeshData* NavMeshManager::initNavMesh(uint32_t mapId)
{
    // Используем умный указатель для автоматического управления памятью
    NavMeshPtr navMesh(dtAllocNavMesh());
    if (!navMesh)
    {
        qCCritical(navMeshLog) << "Failed to allocate dtNavMesh for map" << mapId;
        return nullptr;
    }

    dtNavMeshParams params{};
    std::memcpy(params.orig, WowNavMesh::ORIGIN, sizeof(WowNavMesh::ORIGIN));
    params.tileWidth = WowNavMesh::TILE_SIZE;
    params.tileHeight = WowNavMesh::TILE_SIZE;
    params.maxTiles = WowNavMesh::MAX_TILES;
    params.maxPolys = WowNavMesh::MAX_POLYS;

    dtStatus status = navMesh->init(&params);  // Сохраняем статус для логов
    if (dtStatusFailed(status))
    {
        // Добавляем код ошибки в лог!
        qCCritical(navMeshLog) << "Failed to initialize dtNavMesh with given params. Detour status:" << status;
        return nullptr;
    }

    auto navMeshData = std::make_unique<NavMeshData>();
    navMeshData->navMesh = std::move(navMesh);

    NavMeshData* rawPtr = navMeshData.get();
    m_navMeshes[mapId] = std::move(navMeshData);

    qCInfo(navMeshLog) << "NavMesh for map" << mapId << "initialized successfully.";
    return rawPtr;
}

NavMeshManager::TileDataPtr NavMeshManager::loadTileFile(const std::string& path, int* size)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return nullptr;

    std::streamsize fileSize = file.tellg();
    if (fileSize <= 0) return nullptr;

    file.seekg(0, std::ios::beg);

    TileDataPtr buffer((unsigned char*)dtAlloc(static_cast<size_t>(fileSize), DT_ALLOC_PERM));
    if (!buffer) return nullptr;

    if (!file.read(reinterpret_cast<char*>(buffer.get()), fileSize))
    {
        return nullptr;
    }

    *size = static_cast<int>(fileSize);
    return buffer;
}

std::string NavMeshManager::createTilePath(uint32_t mapId, int tileX, int tileY) const
{
    return m_navMeshBasePath + "/" + std::to_string(mapId) + "/" + std::to_string(tileX) + "_" + std::to_string(tileY) +
           ".navmesh";
}

void NavMeshManager::loadTilesInArea(uint32_t mapId, NavMeshData* data, int tx, int ty)
{
    long tileId = ((long)tx << 16) | ty;
    if (data->loadedTiles.count(tileId))
    {
        return;
    }

    std::string fullPath = createTilePath(mapId, tx, ty);
    int dataSize = 0;
    TileDataPtr tileData = loadTileFile(fullPath, &dataSize);

    if (!tileData)
    {
        data->loadedTiles.insert(tileId);
        return;
    }

    dtMeshHeader* header = reinterpret_cast<dtMeshHeader*>(tileData.get());
    // <<< ДОБАВЬ ЭТОТ ДИАГНОСТИЧЕСКИЙ БЛОК >>>
    qCDebug(navMeshLog) << "--- Loaded Tile Header ---";
    qCDebug(navMeshLog) << "Tile Pos (x, y):" << header->x << header->y;
    qCDebug(navMeshLog) << "Layer/PolyCount:" << header->layer << header->polyCount;
    qCDebug(navMeshLog) << "BMin:" << header->bmin[0] << header->bmin[1] << header->bmin[2];
    qCDebug(navMeshLog) << "BMax:" << header->bmax[0] << header->bmax[1] << header->bmax[2];
    qCDebug(navMeshLog) << "--------------------------";
    if (header->x != tx || header->y != ty)
    {
        qCCritical(navMeshLog) << "NavMesh tile config error: file" << QString::fromStdString(fullPath)
                               << "has header for (" << header->x << "," << header->y << ") but should be for (" << tx
                               << "," << ty << ")";
        data->loadedTiles.insert(tileId);
        return;
    }

    // === ИСПРАВЛЕНИЕ №3 ===
    // Сохраняем указатель перед тем, как отдать владение
    unsigned char* rawTileData = tileData.get();
    dtStatus status = data->navMesh->addTile(rawTileData, dataSize, DT_TILE_FREE_DATA, 0, nullptr);

    if (dtStatusFailed(status))
    {
        qCWarning(navMeshLog) << "Failed to add tile (" << tx << "," << ty << ") from"
                              << QString::fromStdString(fullPath) << "with status" << status;
    }
    else
    {
        // Успешно добавили, теперь умный указатель tileData должен отдать владение Detour'у
        tileData.release();
        qCInfo(navMeshLog) << "Tile (" << tx << "," << ty << ") loaded successfully for map" << mapId;
    }
    // В любом случае помечаем тайл как обработанный
    data->loadedTiles.insert(tileId);
}