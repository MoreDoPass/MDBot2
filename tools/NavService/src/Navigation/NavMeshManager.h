#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <memory>  // Для std::unique_ptr

#include "Utils/Vector.h"  // Убедитесь, что путь правильный

// Включаем заголовочные файлы Detour
#include <DetourNavMesh.h>
#include <DetourNavMeshQuery.h>

// --- Константы для геометрии мира WoW 3.3.5a ---
namespace WowNavMesh
{
// Эти значения определяют, как Recast/Detour работает с координатной сеткой мира.
constexpr float ORIGIN[3] = {-17066.666f, 0.0f, -17066.666f};  // ~ -(51200 / 3.0)
constexpr float TILE_SIZE = 533.33333f;                        // 1600 / 3.0
constexpr int MAX_TILES = 4096;                                // Максимальное количество тайлов в памяти
constexpr int MAX_POLYS = 2048;                                // Максимальное количество полигонов на тайл
}  // namespace WowNavMesh

/**
 * @class NavMeshManager
 * @brief Управляет жизненным циклом и загрузкой тайловых NavMesh данных.
 *
 * Этот класс отвечает за динамическую загрузку тайлов NavMesh для различных карт.
 * Он не является синглтоном, а должен создаваться и управляться владельцем (например, главным классом приложения).
 * Класс является потокобезопасным.
 */
class NavMeshManager
{
   public:
    // Конструктор теперь принимает путь к навмешам
    explicit NavMeshManager(const std::string& navMeshBasePath);
    ~NavMeshManager();

    // Запрещаем копирование и перемещение, т.к. класс управляет ресурсами
    NavMeshManager(const NavMeshManager&) = delete;
    NavMeshManager& operator=(const NavMeshManager&) = delete;
    NavMeshManager(NavMeshManager&&) = delete;
    NavMeshManager& operator=(NavMeshManager&&) = delete;

    /**
     * @brief Получает dtNavMesh для указанной карты.
     * @param mapId ID карты.
     * @return Указатель на объект NavMesh или nullptr в случае ошибки.
     */
    dtNavMesh* getNavMeshForMap(uint32_t mapId);

    /**
     * @brief Гарантирует, что все необходимые для пути тайлы загружены.
     * @param mapId ID карты.
     * @param start Начальная точка пути в координатах WoW.
     * @param end Конечная точка пути в координатах WoW.
     */
    void ensureTilesLoaded(uint32_t mapId, const Vector3& start, const Vector3& end);

   private:
    // --- Умные указатели и кастомные "делитеры" для ресурсов Detour ---
    struct DtNavMeshDeleter
    {
        void operator()(dtNavMesh* ptr) const
        {
            if (ptr) dtFreeNavMesh(ptr);
        }
    };
    using NavMeshPtr = std::unique_ptr<dtNavMesh, DtNavMeshDeleter>;

    struct DtTileDataDeleter
    {
        void operator()(unsigned char* ptr) const
        {
            if (ptr) dtFree(ptr);
        }
    };
    using TileDataPtr = std::unique_ptr<unsigned char, DtTileDataDeleter>;

    // Внутренняя структура для хранения данных одной карты
    struct NavMeshData
    {
        NavMeshPtr navMesh;  // Умный указатель управляет памятью dtNavMesh
        std::set<long> loadedTiles;
    };

    // Приватные вспомогательные методы
    NavMeshData* initNavMesh(uint32_t mapId);
    TileDataPtr loadTileFile(const std::string& path, int* size);
    std::string createTilePath(uint32_t mapId, int tileX, int tileY) const;
    void loadTilesInArea(uint32_t mapId, NavMeshData* data, int tx, int ty);

    std::map<uint32_t, std::unique_ptr<NavMeshData>> m_navMeshes;
    mutable std::mutex m_mutex;
    std::string m_navMeshBasePath;
};