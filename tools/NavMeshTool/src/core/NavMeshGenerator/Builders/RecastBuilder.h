#pragma once

#include <vector>
#include <string>
#include <optional>
#include <memory>

// Подключаем полный заголовочный файл Recast.h, чтобы получить
// полное определение структуры rcConfig и rcPolyMesh.
#include "Recast.h"

// Опережающее объявление (forward declaration) для структуры rcConfig.
// Это позволяет нам использовать указатели или ссылки на rcConfig в заголовке,
// не включая сюда весь тяжелый Recast.h.
// Полное определение rcConfig будет подключено в .cpp файле.
// struct rcConfig; // <-- Больше не нужно, так как мы подключили Recast.h

namespace NavMesh
{

// Умный указатель для автоматического освобождения памяти rcPolyMesh
struct RecastPolyMeshDeleter
{
    void operator()(rcPolyMesh* pmesh) const;
};
using RecastPolyMeshPtr = std::unique_ptr<rcPolyMesh, RecastPolyMeshDeleter>;

/**
 * @struct BuildResult
 * @brief Хранит все результаты сборки NavMesh.
 */
struct BuildResult
{
    std::vector<unsigned char> navmeshData;  ///< Бинарные данные для .navmesh
    RecastPolyMeshPtr polyMesh;              ///< Полигональный меш для .obj
};

/**
 * @class RecastBuilder
 * @brief Инкапсулирует всю логику построения NavMesh с помощью библиотек Recast и Detour.
 *
 * Этот класс является "черным ящиком": он принимает на вход сырую геометрию
 * (вершины, индексы) и конфигурацию, а на выходе предоставляет готовый
 * для использования и сохранения байтовый массив с данными NavMesh.
 * Он ничего не знает о специфике WoW (MPQ, ADT и т.д.), работая только
 * с универсальными геометрическими данными.
 */
class RecastBuilder
{
   public:
    /**
     * @brief Конструктор.
     * @param config Конфигурация Recast, определяющая все параметры будущего
     *               навигационного меша (размер агента, проходимый уклон и т.д.).
     *               Конфигурация копируется внутрь объекта.
     */
    explicit RecastBuilder(const rcConfig& config);

    /**
     * @brief Основной метод, который выполняет всю работу по построению NavMesh.
     * @param vertices Вектор вершин геометрии в формате (x, y, z, x, y, z...).
     *                 Предполагается, что система координат уже приведена к той,
     *                 которую ожидает Recast (Y-up).
     * @param indices Вектор индексов треугольников (i1, i2, i3, i1, i2, i3...).
     * @return std::optional, содержащий структуру BuildResult в случае успеха.
     *         В случае ошибки возвращает std::nullopt.
     */
    std::optional<BuildResult> build(const std::vector<float>& vertices, const std::vector<int>& indices);

   private:
    rcConfig m_config;  ///< Локальная копия конфигурации для построения меша.

    // Сюда в будущем можно добавлять приватные вспомогательные методы,
    // например, для очистки промежуточных данных Recast.
};

}  // namespace NavMesh