#include "NavMeshManager.h"
#include "Logging/Logging.h"
#include <DetourNavMesh.h>
#include <DetourNavMeshBuilder.h>
#include <DetourTileCache.h>
#include <DetourTileCacheBuilder.h>
#include <fstream>
#include <string>

Q_LOGGING_CATEGORY(navMeshManager, "core.navmeshmanager")

// --- Вспомогательные классы для dtTileCache ---

// 1. Аллокатор. Отвечает за выделение и освобождение памяти для тайлов.
class LinearAllocator : public dtTileCacheAlloc
{
    unsigned char* buffer;
    size_t capacity;
    size_t top;

   public:
    LinearAllocator(const size_t cap) : buffer(0), capacity(0), top(0)
    {
        resize(cap);
    }

    ~LinearAllocator()
    {
        dtFree(buffer);
    }

    void resize(const size_t cap)
    {
        if (buffer) dtFree(buffer);
        buffer = (unsigned char*)dtAlloc(cap, DT_ALLOC_PERM);
        capacity = cap;
    }

    void reset() override
    {
        top = 0;
    }

    void* alloc(const size_t size) override
    {
        if (!buffer || top + size > capacity) return 0;
        unsigned char* mem = &buffer[top];
        top += size;
        return mem;
    }

    void free(void* ptr) override
    {
        // Не делаем ничего, память освобождается вся сразу в reset()
    }
};

// 2. Компрессор. Отвечает за "декомпрессию" тайлов, в нашем случае - за чтение с диска.
class TileCacheCompressor : public dtTileCacheCompressor
{
   public:
    TileCacheCompressor() {}
    ~TileCacheCompressor() {}

    int maxCompressedSize(const int bufferSize) override
    {
        return bufferSize;
    }

    dtStatus compress(const unsigned char* buffer, const int bufferSize, unsigned char* compressed,
                      const int maxCompressedSize, int* compressedSize) override
    {
        memcpy(compressed, buffer, bufferSize);
        *compressedSize = bufferSize;
        return DT_SUCCESS;
    }

    dtStatus decompress(const unsigned char* compressed, const int compressedSize, unsigned char* buffer,
                        const int maxBufferSize, int* bufferSize) override
    {
        // Вместо реальной декомпрессии, мы используем 'compressed' как путь к файлу
        std::string path((const char*)compressed, compressedSize);

        std::ifstream file(path, std::ios::binary);
        if (!file)
        {
            return DT_FAILURE;
        }

        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size <= 0 || size > maxBufferSize)
        {
            return DT_FAILURE;
        }

        if (!file.read((char*)buffer, size))
        {
            return DT_FAILURE;
        }

        *bufferSize = size;
        qCDebug(navMeshManager) << "Тайл успешно загружен из" << QString::fromStdString(path);
        return DT_SUCCESS;
    }
};

// 3. Процессор. Нам не нужна постобработка, поэтому он пустой.
class MeshProcess : public dtTileCacheMeshProcess
{
   public:
    MeshProcess() {}
    void process(struct dtNavMeshCreateParams* params, unsigned char* polyAreas, unsigned short* polyFlags) override {}
};

// --- Основная структура данных для NavMeshManager ---

struct NavMeshManager::TileCacheData
{
    dtTileCache* tileCache = nullptr;
    dtNavMesh* navMesh = nullptr;
    LinearAllocator* allocator = nullptr;
    TileCacheCompressor* compressor = nullptr;
    MeshProcess* processor = nullptr;

    ~TileCacheData()
    {
        dtFreeTileCache(tileCache);
        dtFreeNavMesh(navMesh);
        delete allocator;
        delete compressor;
        delete processor;
    }
};

// --- Реализация методов NavMeshManager ---

NavMeshManager::NavMeshManager()
{
    qCInfo(navMeshManager) << "NavMeshManager (тайловый) создан.";
}

NavMeshManager::~NavMeshManager()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto const& [mapId, data] : m_tileCaches)
    {
        qCDebug(navMeshManager) << "Освобождение TileCache для карты" << mapId;
        delete data;
    }
    m_tileCaches.clear();
}

NavMeshManager& NavMeshManager::getInstance()
{
    static NavMeshManager instance;
    return instance;
}

dtNavMesh* NavMeshManager::getNavMeshForMap(uint32_t mapId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_tileCaches.find(mapId) == m_tileCaches.end())
    {
        if (!initTileCache(mapId))
        {
            return nullptr;
        }
    }
    return m_tileCaches[mapId]->navMesh;
}

void NavMeshManager::update(uint32_t mapId, const Vector3& position)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_tileCaches.find(mapId);
    if (it != m_tileCaches.end())
    {
        // Сообщаем Detour, какие тайлы нужно загрузить
        // Это делается через добавление тайлов вручную, а не через update
        int tx, ty;
        it->second->navMesh->calcTileLoc((const float*)&position, &tx, &ty);

        // Загружаем область 3x3 вокруг игрока
        for (int y = ty - 1; y <= ty + 1; ++y)
        {
            for (int x = tx - 1; x <= tx + 1; ++x)
            {
                // Формируем "сжатые" данные - путь к файлу
                std::string path = "navmeshes/" + std::to_string(mapId) + "/" + std::to_string(x) + "_" +
                                   std::to_string(y) + ".navmesh";

                // Проверяем, существует ли файл, чтобы не спамить запросами
                std::ifstream file(path);
                if (file.good())
                {
                    // dtTileCache::addTile использует decompress для загрузки
                    it->second->tileCache->addTile((unsigned char*)path.c_str(), path.length() + 1, 0, nullptr);
                }
            }
        }

        // update() теперь обрабатывает асинхронные добавления/удаления
        it->second->tileCache->update(0, it->second->navMesh);
    }
}

NavMeshManager::TileCacheData* NavMeshManager::initTileCache(uint32_t mapId)
{
    // 1. Создаем и настраиваем dtNavMesh
    dtNavMesh* navMesh = dtAllocNavMesh();
    if (!navMesh)
    { /*...*/
        return nullptr;
    }

    dtNavMeshParams navMeshParams;
    // ... параметры navMeshParams ...
    navMeshParams.orig[0] = -17066.666f;
    navMeshParams.orig[1] = 0;
    navMeshParams.orig[2] = -17066.666f;
    navMeshParams.tileWidth = 533.33333f;
    navMeshParams.tileHeight = 533.33333f;
    navMeshParams.maxTiles = 4096;
    navMeshParams.maxPolys = 16384;

    if (dtStatusFailed(navMesh->init(&navMeshParams)))
    { /*...*/
        return nullptr;
    }

    // 2. Создаем и настраиваем dtTileCache
    dtTileCache* tileCache = dtAllocTileCache();
    if (!tileCache)
    { /*...*/
        return nullptr;
    }

    dtTileCacheParams tileCacheParams;
    // ... параметры tileCacheParams ...
    memset(&tileCacheParams, 0, sizeof(tileCacheParams));
    tileCacheParams.ch = 0.4f;
    tileCacheParams.cs = 0.2f;
    memcpy(tileCacheParams.orig, navMeshParams.orig, sizeof(navMeshParams.orig));
    tileCacheParams.height = navMeshParams.tileHeight;
    tileCacheParams.width = navMeshParams.tileWidth;
    tileCacheParams.maxTiles = navMeshParams.maxTiles;
    tileCacheParams.maxObstacles = 0;

    auto allocator = new LinearAllocator(32000);  // 32KB
    auto compressor = new TileCacheCompressor();
    auto processor = new MeshProcess();

    if (dtStatusFailed(tileCache->init(&tileCacheParams, allocator, compressor, processor)))
    {
        qCCritical(navMeshManager) << "Не удалось инициализировать dtTileCache";
        delete allocator;
        delete compressor;
        delete processor;
        dtFreeNavMesh(navMesh);
        dtFreeTileCache(tileCache);
        return nullptr;
    }

    // 3. Сохраняем все
    auto data = new TileCacheData();
    data->navMesh = navMesh;
    data->tileCache = tileCache;
    data->allocator = allocator;
    data->compressor = compressor;
    data->processor = processor;

    m_tileCaches[mapId] = data;

    qCInfo(navMeshManager) << "TileCache для карты" << mapId << "успешно инициализирован.";
    return data;
}