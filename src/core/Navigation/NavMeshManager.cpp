#include "NavMeshManager.h"
#include "Logging/Logging.h"
#include <DetourNavMesh.h>
#include <DetourNavMeshBuilder.h>
#include <fstream>
#include <QCoreApplication>
#include <QDir>

Q_LOGGING_CATEGORY(navMeshManager, "core.navmeshmanager")

// --- Реализация методов NavMeshManager ---

NavMeshManager::NavMeshManager()
{
    qCInfo(navMeshManager) << "NavMeshManager (прямая загрузка) создан.";
}

NavMeshManager::~NavMeshManager()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto const& [mapId, data] : m_navMeshes)
    {
        qCDebug(navMeshManager) << "Освобождение NavMesh для карты" << mapId;
        dtFreeNavMesh(data->navMesh);
        delete data;
    }
    m_navMeshes.clear();
}

NavMeshManager& NavMeshManager::getInstance()
{
    static NavMeshManager instance;
    return instance;
}

dtNavMesh* NavMeshManager::getNavMeshForMap(uint32_t mapId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_navMeshes.find(mapId) == m_navMeshes.end())
    {
        if (!initNavMesh(mapId))
        {
            qCCritical(navMeshManager) << "Не удалось инициализировать NavMesh для карты" << mapId;
            return nullptr;
        }
    }
    return m_navMeshes[mapId]->navMesh;
}

void NavMeshManager::update(uint32_t mapId, const Vector3& position)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_navMeshes.find(mapId);
    if (it != m_navMeshes.end())
    {
        NavMeshData* data = it->second;

        float recastPos[3] = {position.x, position.z, -position.y};
        int tx, ty;
        data->navMesh->calcTileLoc(recastPos, &tx, &ty);
        qCDebug(navMeshManager) << "Центральный тайл для позиции" << position.x << position.y << position.z << "-> ("
                                << tx << "," << ty << ")";

        // Загружаем область 3x3 вокруг игрока
        for (int y = ty - 1; y <= ty + 1; ++y)
        {
            for (int x = tx - 1; x <= tx + 1; ++x)
            {
                long tileId = ((long)x << 16) | y;
                if (data->loadedTiles.count(tileId))
                {
                    continue;  // Тайл уже загружен
                }

                QString fullPath = QDir(QCoreApplication::applicationDirPath())
                                       .filePath(QString("navmeshes/%1/%2_%3.navmesh").arg(mapId).arg(x).arg(y));
                std::string pathStr = fullPath.toStdString();

                int dataSize = 0;
                unsigned char* tileData = loadFile(pathStr, &dataSize);

                if (tileData)
                {
                    // --- РЕШАЮЩАЯ ПРОВЕРКА ---
                    if (dataSize < sizeof(dtMeshHeader))
                    {
                        qCWarning(navMeshManager)
                            << "Файл тайла" << fullPath << "слишком мал, чтобы содержать заголовок.";
                        dtFree(tileData);
                        continue;
                    }

                    dtMeshHeader* header = reinterpret_cast<dtMeshHeader*>(tileData);

                    qCDebug(navMeshManager)
                        << "Проверка тайла (" << x << "," << y << "): Заголовок файла говорит, что он для ("
                        << header->x << "," << header->y << ").";

                    // Проверяем, совпадают ли координаты из имени файла с координатами из заголовка
                    if (header->x != x || header->y != y)
                    {
                        qCCritical(navMeshManager)
                            << "КРИТИЧЕСКАЯ ОШИБКА КОНФИГУРАЦИИ NAVMESH: Координаты тайла в имени файла (" << x << ","
                            << y << ") НЕ СОВПАДАЮТ с координатами в его заголовке (" << header->x << "," << header->y
                            << ")! Файл:" << fullPath;
                        qCCritical(navMeshManager) << "Это означает, что NavMeshTool некорректно сохранил тайлы. "
                                                      "Пропускаем этот тайл, чтобы избежать падения.";
                        dtFree(tileData);
                        data->loadedTiles.insert(tileId);  // Помечаем как "загруженный", чтобы не пытаться снова
                        continue;
                    }
                    // --- КОНЕЦ ПРОВЕРКИ ---

                    qCDebug(navMeshManager)
                        << "Попытка добавить тайл (" << x << "," << y << "). Полигонов в файле:" << header->polyCount
                        << "| Макс. разрешено:" << data->navMesh->getParams()->maxPolys;
                    dtStatus status = data->navMesh->addTile(tileData, dataSize, DT_TILE_FREE_DATA, 0, nullptr);
                    if (dtStatusFailed(status))
                    {
                        qCWarning(navMeshManager)
                            << "Не удалось добавить тайл (" << x << "," << y << "). Статус:" << status;
                        dtFree(tileData);
                    }
                    else
                    {
                        qCInfo(navMeshManager) << "Тайл (" << x << "," << y << ") успешно добавлен в NavMesh.";
                        data->loadedTiles.insert(tileId);
                    }
                }
            }
        }
    }
}

unsigned char* NavMeshManager::loadFile(const std::string& path, int* size)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
    {
        return nullptr;
    }

    std::streamsize fileSize = file.tellg();
    if (fileSize <= 0)
    {
        file.close();
        return nullptr;
    }
    file.seekg(0, std::ios::beg);

    unsigned char* buffer = (unsigned char*)dtAlloc(static_cast<size_t>(fileSize), DT_ALLOC_PERM);
    if (!buffer)
    {
        file.close();
        return nullptr;
    }

    if (!file.read(reinterpret_cast<char*>(buffer), fileSize))
    {
        file.close();
        dtFree(buffer);
        return nullptr;
    }

    file.close();
    *size = static_cast<int>(fileSize);
    return buffer;
}

NavMeshManager::NavMeshData* NavMeshManager::initNavMesh(uint32_t mapId)
{
    dtNavMesh* navMesh = dtAllocNavMesh();
    if (!navMesh)
    {
        qCCritical(navMeshManager) << "Не удалось выделить память для dtNavMesh (dtAllocNavMesh вернул nullptr)";
        return nullptr;
    }

    dtNavMeshParams navMeshParams;

    navMeshParams.orig[0] = -17066.666f;
    navMeshParams.orig[1] = 0.0f;
    navMeshParams.orig[2] = -17066.666f;
    navMeshParams.tileWidth = 533.33333f;
    navMeshParams.tileHeight = 533.33333f;
    navMeshParams.maxTiles = 4096;
    navMeshParams.maxPolys = 2048;

    dtStatus status = navMesh->init(&navMeshParams);
    if (dtStatusFailed(status))
    {
        qCCritical(navMeshManager) << "Не удалось инициализировать dtNavMesh. Код ошибки:" << status;
        dtFreeNavMesh(navMesh);
        return nullptr;
    }

    auto data = new NavMeshData();
    data->navMesh = navMesh;

    m_navMeshes[mapId] = data;

    qCInfo(navMeshManager) << "NavMesh для карты" << mapId << "успешно инициализирован.";
    return data;
}
