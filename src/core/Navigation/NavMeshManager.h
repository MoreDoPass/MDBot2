#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include "Utils/Vector.h"  // Для Vector3

// Прямые объявления, чтобы не делать заголовок слишком тяжелым
class dtNavMesh;
class dtNavMeshQuery;

/**
 * @class NavMeshManager
 * @brief Потокобезопасный синглтон для управления тайловыми NavMesh данными.
 *
 * Этот класс отвечает за динамическую загрузку тайлов NavMesh для различных карт (mapId)
 * напрямую в dtNavMesh. Он держит в памяти только необходимые тайлы вокруг персонажа.
 * В отличие от предыдущей реализации, этот класс НЕ использует dtTileCache, так как
 * мы работаем с уже готовыми, "запеченными" тайлами, а не со слоями данных.
 */
class NavMeshManager
{
   public:
    static NavMeshManager& getInstance();

    /**
     * @brief Получает dtNavMesh для указанной карты.
     *
     * Если NavMesh для карты еще не создан, он будет инициализирован.
     * Возвращаемый указатель управляется NavMeshManager'ом и не должен удаляться извне.
     *
     * @param mapId - ID карты.
     * @return dtNavMesh* - указатель на объект NavMesh или nullptr в случае ошибки.
     */
    dtNavMesh* getNavMeshForMap(uint32_t mapId);

    /**
     * @brief Периодически вызываемый метод для загрузки тайлов вокруг игрока.
     *
     * На основе позиции игрока вычисляет, какие тайлы должны быть загружены,
     * и подгружает их с диска, если они еще не в памяти.
     *
     * @param mapId - ID текущей карты игрока.
     * @param position - Актуальная позиция игрока.
     */
    void update(uint32_t mapId, const Vector3& position);

   private:
    NavMeshManager();
    ~NavMeshManager();

    NavMeshManager(const NavMeshManager&) = delete;
    NavMeshManager& operator=(const NavMeshManager&) = delete;

    // Внутренняя структура для хранения всех данных, связанных с одной картой
    struct NavMeshData
    {
        dtNavMesh* navMesh = nullptr;
        std::set<long> loadedTiles;  // Храним тайлы по ключу (x << 16) | y

        ~NavMeshData()
        {
            // dtFreeNavMesh будет вызван в деструкторе NavMeshManager
        }
    };

    /**
     * @brief Инициализирует dtNavMesh для новой карты.
     * @param mapId - ID карты.
     * @return NavMeshData* - указатель на созданную структуру.
     */
    NavMeshData* initNavMesh(uint32_t mapId);

    /**
     * @brief Загружает файл с диска в буфер.
     * @param path - Путь к файлу.
     * @param[out] size - Размер загруженных данных.
     * @return unsigned char* - Указатель на буфер с данными или nullptr в случае ошибки.
     * @note Вызывающий код отвечает за освобождение памяти буфера с помощью delete[].
     */
    unsigned char* loadFile(const std::string& path, int* size);

    std::map<uint32_t, NavMeshData*> m_navMeshes;  ///< Кэш, где для каждого mapId хранится свой NavMesh.
    std::mutex m_mutex;                            ///< Мьютекс для обеспечения потокобезопасности.
};
