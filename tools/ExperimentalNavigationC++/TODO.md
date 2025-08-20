TODO: Переход на std::unordered_set для быстрого поиска пути
Цель: Заменить медленный std::vector в нашей разреженной сетке на быстрый std::unordered_set. Это позволит Pathfinder-у работать с приемлемой скоростью, решив проблему "зависаний".
Шаг 1: Модификация структуры SimpleSparseGrid
Файл: src/core/math/Types.h
Задача: В структуре SimpleSparseGrid заменить std::vector на std::unordered_set.
Что сделать:
Добавить #include <unordered_set> в начало файла Types.h.
Найти структуру SimpleSparseGrid.
Заменить строчку:
std::vector<VoxelCoord> solidVoxels;
на:
std::unordered_set<VoxelCoord> solidVoxels;
Комментарий: Теперь solidVoxels — это не просто список, а наша быстрая "картотека" (хэш-таблица).
Шаг 2: Адаптация Voxelizer-а к новой структуре
Файл: src/core/generator/pipeline/Voxelizer.cpp
Задача: В методе ConvertToSparseGrid добавлять воксели в unordered_set вместо vector.
Что сделать:
Найти реализацию функции Voxelizer::ConvertToSparseGrid.
Заменить строчку:
sparseGrid.solidVoxels.push_back({x, y, z});
на:
sparseGrid.solidVoxels.insert({x, y, z});
Комментарий: unordered_set использует метод .insert() для добавления элементов, а не .push_back(). В остальном логика функции не меняется.
Шаг 3: Модификация NavMeshGenerator-а
Файл: src/core/generator/NavMeshGenerator.cpp и NavMeshGenerator.h
Задача: Адаптировать NavMeshGenerator для хранения и проверки проходимости через unordered_set.
Что сделать в NavMeshGenerator.h:
Поменять тип поля m_sparseSolidGrid с SimpleSparseGrid на std::unordered_set<VoxelCoord>. Или создать новое поле m_walkableSet.
Важно: Для m_voxelCosts мы оставляем std::vector. Нам нужен unordered_set именно для walkable вокселей, а не для стоимостей. Предлагаю создать новое поле, чтобы не было путаницы:
code
C++
private:
    // ... другие поля ...
    
    /// @brief Быстрая хэш-таблица для проверки проходимости вокселя.
    std::unordered_set<VoxelCoord> m_walkableVoxels; 
```*   **Что сделать в `NavMeshGenerator.cpp` (функция `build`):**
В конце конвейера, после radiusFilteredGrid, мы конвертируем результат не в локальную переменную, а сразу в наш новый член класса m_walkableVoxels.
code
C++
// ... после получения radiusFilteredGrid ...
SimpleSparseGrid sparseWalkableGrid = Voxelizer::ConvertToSparseGrid(radiusFilteredGrid);
m_walkableVoxels = std::move(sparseWalkableGrid.solidVoxels); 
// std::move - это эффективный способ "переместить" данные без копирования

qInfo(lcCore) << "Created a fast lookup set with" << m_walkableVoxels.size() << "walkable voxels.";
Переписать метод isWalkable:
Старая версия смотрела в m_voxelCosts. Новая, быстрая, должна смотреть в наш set.
code
C++
bool NavMeshGenerator::isWalkable(int x, int y, int z) const {
    VoxelCoord coord_to_find = {x, y, z};
    return m_walkableVoxels.count(coord_to_find) > 0;
}
Комментарий: Метод .count() для unordered_set работает практически мгновенно. Он вернет 1, если элемент найден, и 0, если нет.
Шаг 4: Адаптация Pathfinder-а
Файл: src/core/pathfinder/Pathfinder.cpp
Задача: Изменить Pathfinder, чтобы для проверки проходимости он использовал новый быстрый метод generator->isWalkable().
Что сделать:
Найти цикл по соседям в функции findPath.
Заменить строчку:
uint8_t cost = generator->getVoxelCost(nx, ny, nz);
if (cost > 0)
на:
if (generator->isWalkable(nx, ny, nz))
Так как мы теперь не получаем стоимость, нужно ее задать. Для простоты пока что считаем, что стоимость любого шага равна 1.
double new_g = current.g + move_cost; // move_cost - это длина шага
Комментарий: Pathfinder больше не работает с "медленными" voxelCosts, а напрямую использует "быструю" проверку isWalkable, которая внутри себя обращается к unordered_set.
После выполнения этих шагов Pathfinder будет работать на порядки быстрее на больших картах, и проблема с зависаниями при поиске пути должна исчезнуть. Проблема с объемом памяти (36 МБ) останется, но мы решим ее позже с помощью октодерева.