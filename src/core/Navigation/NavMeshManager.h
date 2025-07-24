#pragma once

#include <map>
#include <mutex>
#include <cstdint>
#include "Utils/Vector.h"  // Для Vector3

// Прямые объявления, чтобы не делать заголовок слишком тяжелым
class dtNavMesh;
class dtTileCache;
class dtNavMeshQuery;

/**
 * @class NavMeshManager
 * @brief Потокобезопасный синглтон для управления тайловыми NavMesh данными.
 *
 * Этот класс отвечает за динамическую загрузку и выгрузку тайлов NavMesh для различных карт (mapId)
 * с использованием dtTileCache. Он держит в памяти только необходимые тайлы вокруг персонажа,
 * что значительно экономит память при работе с большими континентами.
 */
class NavMeshManager
{
   public:
    static NavMeshManager& getInstance();

    /**
     * @brief Получает dtNavMesh для указанной карты.
     *
     * Если кэш для карты еще не создан, он будет инициализирован.
     * Возвращаемый указатель управляется NavMeshManager'ом и не должен удаляться извне.
     *
     * @param mapId - ID карты.
     * @return dtNavMesh* - указатель на объект NavMesh или nullptr в случае ошибки.
     */
    dtNavMesh* getNavMeshForMap(uint32_t mapId);

    /**
     * @brief Периодически вызываемый метод для обновления кэша тайлов.
     *
     * Сообщает dtTileCache актуальную позицию игрока, чтобы тот мог
     * подгрузить нужные и выгрузить ненужные тайлы.
     *
     * @param mapId - ID текущей карты игрока.
     * @param position - Актуальная позиция игрока.
     */
    void update(uint32_t mapId, const Vector3& position);

   private:
    NavMeshManager();  // Конструктор теперь приватный и не default, т.к. нужна логика
    ~NavMeshManager();

    NavMeshManager(const NavMeshManager&) = delete;
    NavMeshManager& operator=(const NavMeshManager&) = delete;

    // Внутренняя структура для хранения всех данных, связанных с одной картой
    struct TileCacheData;

    /**
     * @brief Инициализирует кэш тайлов для новой карты.
     * @param mapId - ID карты.
     * @return TileCacheData* - указатель на созданную структуру данных кэша.
     */
    TileCacheData* initTileCache(uint32_t mapId);

    std::map<uint32_t, TileCacheData*> m_tileCaches;  ///< Кэш, где для каждого mapId хранится свой TileCache.
    std::mutex m_mutex;                               ///< Мьютекс для обеспечения потокобезопасности.
};