# Анализ трансформаций ландшафта WoW

## Структура MCNK чанка

### Заголовок MCNK (128 байт)

- Смещения для координат:
  - xpos: 0x6C (X координата в мире)
  - zpos: 0x68 (Y координата в мире)
  - ypos: 0x70 (Z/высота в мире)

### Чанк MCVT (высоты)

- Смещение к MCVT: 0x14 в заголовке MCNK
- Содержит 145 значений float для высот
- Высоты добавляются к базовой высоте чанка (ypos)
- Формирует сетку 9x9 + 8x8 точек для одного чанка

### Система координат в .adt

- Координаты в .adt файлах хранятся в локальной системе координат чанка
- Каждый чанк имеет свои базовые координаты (xpos, zpos, ypos)
- Высоты из MCVT добавляются к базовой высоте чанка
- Итоговые координаты точки = [xpos, zpos, ypos + height]

## Трансформации для совпадения с игрой

Для корректного отображения ландшафта относительно координат в игре необходимо:

1. Отзеркалить ландшафт по оси X
2. Повернуть на 270 градусов против часовой стрелки

## Почему нужны именно эти трансформации?

1. **Зеркальность по X**:
   - В игре используется левосторонняя система координат (DirectX)
   - В .adt файлах - правосторонняя система координат (OpenGL)
   - Отражение по X приводит к правильной ориентации осей
   - Это как отражение в зеркале - все X координаты меняют знак

2. **Поворот на 270 градусов**:
   - В игре ось Y направлена на север
   - В .adt файлах ось Y направлена на восток
   - Поворот на 270 градусов против часовой стрелки выравнивает оси по направлению севера
   - Это как повернуть карту, чтобы север был вверху

## Константы для работы с ландшафтом

```python
TILE_SIZE = 1600.0 / 3.0  # ~533.33333 ярдов
MCNK_SIZE_UNITS = TILE_SIZE / 16.0  # ~33.33333 ярдов
UNIT_SIZE = MCNK_SIZE_UNITS / 8.0  # ~4.16666 ярдов
```

## Порядок применения трансформаций

1. Сначала отражение по X (меняем знак X координаты)
2. Затем поворот на 270 градусов против часовой стрелки
3. Точки в игре добавляются в оригинальных координатах без трансформаций

## Важные замечания

1. **Порядок трансформаций критичен**:
   - Сначала отражение, потом поворот
   - Если сделать наоборот, результат будет неправильным

2. **Точки в игре**:
   - Уже находятся в правильной системе координат
   - Не требуют трансформаций
   - Используются как эталон для проверки правильности трансформаций ландшафта

3. **Проверка трансформаций**:
   - После трансформаций ландшафт должен совпадать с точками в игре
   - Если точка в игре находится на координатах (X, Y, Z), то после трансформаций ландшафта эта точка должна оказаться в правильном месте на ландшафте

```cpp
bool NavMeshGenerator::testAdtRawCoordinatesWithMirrorAndRotation(const std::string& mapName)
{
    // Очищаем предыдущие данные
    m_worldVertices.clear();
    m_worldTriangleIndices.clear();

    // 1. Загрузка и парсинг WDT
    std::string wdtPath = "World\\maps\\" + mapName + "\\" + mapName + ".wdt";
    std::vector<unsigned char> wdtBuffer;

    if (!m_mpqManager.readFile(wdtPath, wdtBuffer))
    {
        qCritical(logNavMeshGenerator) << "Failed to read WDT file:" << QString::fromStdString(wdtPath);
        return false;
    }

    auto wdtDataOpt = m_wdtParser.parse(wdtBuffer, mapName);
    if (!wdtDataOpt)
    {
        qCritical(logNavMeshGenerator) << "Failed to parse WDT file:" << QString::fromStdString(wdtPath);
        return false;
    }
    m_currentWdtData = *wdtDataOpt;

    // 2. Основной цикл загрузки ADT
    for (const auto& adtEntry : m_currentWdtData.adtFilenames)
    {
        const std::string& adtFileName = adtEntry.filename;
        qDebug(logNavMeshGenerator) << "Processing ADT:" << QString::fromStdString(adtFileName) << "Coords:("
                                    << adtEntry.x << "," << adtEntry.y << ")";

        // Читаем файл ADT из MPQ
        std::vector<unsigned char> adtBuffer;
        if (!m_mpqManager.readFile(adtFileName, adtBuffer))
        {
            qWarning(logNavMeshGenerator) << "Could not read ADT file:" << QString::fromStdString(adtFileName);
            continue;
        }

        // Парсим ADT
        auto adtDataOpt = m_adtParser.parse(adtBuffer, adtFileName);
        if (!adtDataOpt)
        {
            qWarning(logNavMeshGenerator) << "Could not parse ADT file:" << QString::fromStdString(adtFileName);
            continue;
        }

        // Проходим по каждому чанку
        for (const auto& mcnk : adtDataOpt->mcnkChunks)
        {
            // 1.4) Сырые координаты + инверсия по X + поворот на 270
            float x = mcnk.header.xpos;
            float y = mcnk.header.zpos;
            float z = mcnk.header.ypos;

            // Инверсия по X
            x = -x;

            // Поворот на 270 градусов
            float newX = y;  // cos(270) = 0, sin(270) = -1
            float newY = -x;

            m_worldVertices.push_back(newX);
            m_worldVertices.push_back(newY);
            m_worldVertices.push_back(z);
        }
    }

    // Сохраняем результат
    return saveToObj("output/obj/test/raw_coordinates_with_mirror_and_rotation.obj");
}
```
