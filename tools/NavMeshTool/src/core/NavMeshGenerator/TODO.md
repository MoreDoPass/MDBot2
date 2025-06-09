# План работ для NavMeshGenerator

Этот файл описывает высокоуровневый план по реализации `NavMeshGenerator`.

## Фаза 1: Рефакторинг зависимостей (Завершено)

Все парсеры (`WDT`, `ADT`, `M2`, `WMO`) были успешно рефакторены и готовы к использованию.

- [x] Рефакторинг `WDTParser`
- [x] Рефакторинг `ADTParser`
- [x] Рефакторинг `M2Parser`
- [x] Рефакторинг `WMOParser`

## Фаза 2: Реализация логики загрузки геометрии

Эта фаза фокусируется на наполнении `m_worldVertices` и `m_worldTriangleIndices` из всех источников геометрии карты.

- [x] **1. Реализовать основной цикл загрузки ADT в `loadMapData`:**
  - [x] После успешного парсинга WDT, создать цикл по `m_currentWdtData.adtFileNames`.
  - [x] Внутри цикла для каждого `adtFileName`:
    - [x] Сформировать полный путь к ADT файлу (например, `World\maps\expansion01\expansion01_30_30.adt`).
    - [x] Использовать `m_mpqManager` для чтения файла в буфер.
    - [x] Вызвать `m_adtParser.parse(buffer)` и получить `adtData`.
    - [x] **Action:** Если `adtData` получены, вызвать новую приватную функцию `processAdtChunk(*adtData, adt_row, adt_col)`.

- [ ] **2. Создать и реализовать `processAdtChunk(const ADTData& adtData, int row, int col)`:**
  - [ ] Этот метод будет оркестратором для обработки одного тайла карты.
  - [ ] Он должен последовательно вызывать:
    - [ ] `processAdtTerrain(adtData, row, col)`
    - [ ] `processAdtWmos(adtData)`
    - [ ] `processAdtM2s(adtData)`

- [ ] **3. Реализовать `processAdtTerrain(const ADTData& adtData, int row, int col)`:**
  - [ ] Получить вершины и индексы из `adtData.terrain.vertices` и `adtData.terrain.indices`.
  - [ ] **(Сложно)** Трансформировать каждую вершину из локальных координат тайла в мировые. Для этого нужно знать глобальные координаты угла ADT, которые вычисляются на основе `row`, `col` и констант размера тайла.
  - [ ] Перед добавлением в `m_worldVertices` запомнить текущий размер этого вектора (`vertexOffset`).
  - [ ] Добавить трансформированные вершины в `m_worldVertices`.
  - [ ] Добавить индексы в `m_worldTriangleIndices`, прибавив к каждому индексу `vertexOffset`.

- [ ] **4. Реализовать `processAdtWmos(const ADTData& adtData)`:**
  - [ ] Пройти в цикле по списку WMO-объектов из `adtData.wmo_definitions`.
  - [ ] Для каждого WMO (`wmoDef`):
    - [ ] Прочитать его корневой `.wmo` файл.
    - [ ] **(Ключевая архитектура)** Создать `fileProvider` (лямбда-функцию), которая "захватывает" `m_mpqManager`.
    - [ ] Вызвать `m_wmoParser.parse(wmoDef.name, wmoBuffer, fileProvider)` и получить `wmoData`.
    - [ ] Получить информацию о размещении этого WMO из `wmoDef`.
    - [ ] Трансформировать **каждую** вершину из `wmoData.vertices` в мировые координаты, используя матрицу трансформации, построенную на основе данных о размещении WMO.
    - [ ] Добавить трансформированные вершины и скорректированные индексы в `m_worldVertices` и `m_worldTriangleIndices`.

- [ ] **5. Реализовать `processAdtM2s(const ADTData& adtData)`:**
  - [ ] Сделать то же самое, что и в `processAdtWmos`, но для списка M2-моделей (`adtData.m2_definitions`).
  - [ ] Каждый M2 парсится индивидуально (`m_m2Parser.parse`), его вершины трансформируются и добавляются в общие векторы.

- [ ] **6. Реализовать обработку глобального WMO:**
  - [ ] После основного цикла по ADT, проверить наличие глобального WMO в `m_currentWdtData`.
  - [ ] Если он есть, загрузить и обработать его аналогично `processAdtWmos`, используя информацию о размещении из `m_currentWdtData.modf`.

## Фаза 3: Построение NavMesh

- [ ] Когда вся геометрия карты собрана в `m_worldVertices` и `m_worldTriangleIndices`:
  - [ ] Передать эти данные в библиотеку Recast & Detour.
  - [ ] Настроить параметры построения сетки (размер агента, высота и т.д.).
  - [ ] Запустить процесс построения NavMesh.
  - [ ] Сохранить готовую навигационную сетку в файл.
