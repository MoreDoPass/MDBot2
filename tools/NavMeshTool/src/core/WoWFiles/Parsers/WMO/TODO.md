# План рефакторинга WMO-парсера

## Этап 1: Редизайн API и структур данных в `WMOParser.h`

- [ ] **Объединение структур:**
  - [ ] Создать новую основную структуру `WmoData`, которая будет содержать всю информацию (геометрию, метаданные, группы, дудады).
  - [ ] Устаревшие структуры `WmoRootData` и `WmoGeometry` будут либо интегрированы в `WmoData`, либо удалены.
- [ ] **Определение `FileProvider`:**
  - [ ] Ввести `using FileProvider = std::function<...>;` для функции, которая будет поставлять данные зависимых файлов.
- [ ] **Обновление класса `Parser`:**
  - [ ] Изменить публичный метод на `std::optional<WmoData> parse(const std::vector<unsigned char>& rootWmoBuffer, const FileProvider& fileProvider) const;`.
  - [ ] Удалить все старые `get_*` методы и внутренние поля, хранящие состояние (`m_root_data`, `m_final_geometry` и т.д.). Парсер должен стать "stateless".
  - [ ] Удалить `M2Parser` как член класса.

## Этап 2: Реализация парсинга корневого WMO в `WMOParser.cpp`

- [ ] Реализовать внутренний метод `parseRoot`, который принимает буфер и парсит только чанки корневого WMO (MOHD, MOGI, и т.д.), возвращая временную структуру с метаданными.
- [ ] Основной метод `parse` должен вызывать `parseRoot`, обрабатывать его результат и возвращать `WmoData`, пока что без геометрии групп и M2.

## Этап 3: Реализация парсинга зависимостей через `FileProvider`

- [ ] **Парсинг групп:**
  - [ ] В главном методе `parse` организовать цикл по списку групп (из `parseRoot`).
  - [ ] Внутри цикла вызывать `fileProvider` для получения буфера каждой группы.
  - [ ] Если буфер получен, вызывать внутренний метод `parseGroup` и добавлять геометрию в `WmoData`.
- [ ] **Парсинг M2-дудадов:**
  - [ ] Аналогично группам, организовать цикл по списку M2-моделей.
  - [ ] Вызывать `fileProvider` для получения буфера каждого M2.
  - [ ] Если буфер получен, создавать **локальный** экземпляр `M2::Parser`, парсить буфер и добавлять геометрию в `WmoData`.

## Этап 4: Адаптация тестов `TestWMOParser.cpp`

- [ ] Модифицировать тестовый класс, чтобы он перед запуском теста загружал все необходимые WMO и M2 файлы в `std::map`.
- [ ] Создать лямбда-функцию, которая будет служить в качестве `fileProvider`, "захватив" этот `map`.
- [ ] Переписать тестовые случаи, чтобы они вызывали новый метод `parser.parse()` и проверяли данные из возвращаемой структуры `WmoData`.
