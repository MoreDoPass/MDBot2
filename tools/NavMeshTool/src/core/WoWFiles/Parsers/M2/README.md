# Структура файла .M2 (версия для WotLK 3.3.5a)

Этот документ описывает структуру файлов моделей `.M2`, используемых в World of Warcraft WotLK 3.3.5a, на основе анализа вывода скрипта `m2_parser.py`, данных с [wowdev.wiki/M2](https://wowdev.wiki/M2) и анализа hex-дампов.

## Общие принципы

* **Порядок байт (Endianness):** Все числовые данные в M2 файлах хранятся в **Little Endian** порядке.
* **Структура файла:** M2 файл для WotLK (версия 264) не является чанковым в привычном понимании (как ADT). Он состоит из одного основного, фиксированного по размеру заголовка, за которым следуют различные блоки данных (геометрия, текстуры, анимации и т.д.). Смещения к этим блокам данных хранятся непосредственно в полях заголовка.
* **Анализ:** Данный документ является результатом предварительного анализа и будет дополняться.

## 1. Структура M2_Header_WotLK (Основной заголовок M2)

Заголовок M2 файла (`M2_Header_WotLK`) для версии 264 (WotLK 3.3.5a) имеет фиксированный размер **264 байта (0x108)**.
Он содержит основную метаинформацию о модели, флаги, а также пары "количество элементов" и "смещение" для доступа к основным блокам данных модели, расположенным далее в файле.

```cpp
// Предварительное определение для C3Vector и CAaBox, используемых в заголовке
struct C3Vector {
    float x, y, z;
};

struct CAaBox { // Axis-Aligned Bounding Box
    C3Vector min_corner;
    C3Vector max_corner;
};

// M2Array<T> - это концептуальное представление для пары { uint32_t count; uint32_t offset; }

struct M2_Header_WotLK { // Размер 0x108 (264 байта) для версии 264 (WotLK)
    // ---- Идентификатор и версия (0x00 - 0x07) ----
    char     magic[4];                // 0x00: "MD20" - Магическое число.
    uint32_t version;                 // 0x04: Версия формата M2 (264 для WotLK).

    // ---- Имя модели (M2Array<char>) (0x08 - 0x0F) ----
    uint32_t length_model_name;       // 0x08: Длина имени модели в символах.
    uint32_t offset_model_name;       // 0x0C: Смещение к строке имени модели от начала файла.
                                      //       (Обычно 0x130, т.е. за пределами этого заголовка)

    // ---- Флаги модели (0x10 - 0x13) ----
    uint32_t model_flags;             // 0x10: GlobalModelFlags (битовые флаги).
                                      //       Известные флаги (неполный список, см. wowdev.wiki для GlobalModelFlags):
                                      //         - 0x1: Use_LOD (использовать уровни детализации, если есть)
                                      //         - 0x8: Has_collision_volume (модель имеет геометрию столкновений; очень важно для NavMesh)
                                      //         - 0x10: (cataclysm+) ignore ambient light
                                      //         - 0x20: Has_lights (модель использует источники света, см. блок M2Light)
                                      //         - 0x20000: Is_Mount (модель является средством передвижения)
                                      //       Флаг 0x8 особенно важен для NavMesh, так как он указывает на то, что модель должна иметь осмысленную геометрию столкновений.

    // ---- Глобальные последовательности (M2Array<M2Loop>) (0x14 - 0x1B) ----
    uint32_t num_global_sequences;    // 0x14: Количество глобальных циклов анимаций.
    uint32_t offset_global_sequences; // 0x18: Смещение к данным глобальных циклов.

    // ---- Анимации (M2Array<M2Sequence>) (0x1C - 0x23) ----
    uint32_t num_animations;          // 0x1C: Количество блоков анимаций.
    uint32_t offset_animations;       // 0x20: Смещение к данным анимаций.

    // ---- Таблица поиска анимаций (M2Array<uint16_t>) (0x24 - 0x2B) ----
    uint32_t num_animation_lookup;    // 0x24: Количество записей в таблице поиска анимаций.
    uint32_t offset_animation_lookup; // 0x28: Смещение к таблице поиска анимаций.

    // ---- Кости (M2Array<M2CompBone>) (0x2C - 0x33) ----
    uint32_t num_bones;               // 0x2C: Количество костей.
    uint32_t offset_bones;            // 0x30: Смещение к данным костей.

    // ---- Таблица поиска ключевых костей (M2Array<uint16_t>) (0x34 - 0x3B) ----
    uint32_t num_key_bone_lookup;     // 0x34: Количество записей в таблице поиска ключевых костей.
    uint32_t offset_key_bone_lookup;  // 0x38: Смещение к таблице поиска ключевых костей.

    // ---- Вершины (M2Array<M2Vertex>) (0x3C - 0x43) ----
    uint32_t num_vertices;            // 0x3C: Количество вершин.
    uint32_t offset_vertices;         // 0x40: Смещение к данным вершин.

    // ---- "Виды" или "Скины" (LOD) (0x44 - 0x47) ----
    uint32_t num_views;               // 0x44: Количество профилей скинов (LOD). Для WotLK LODы в .skin файлах.

    // ---- Цвета вершин (M2Array<M2Color>) (0x48 - 0x4F) ----
    uint32_t num_colors;              // 0x48: Количество структур данных о цвете.
    uint32_t offset_colors;           // 0x4C: Смещение к данным о цвете.

    // ---- Текстуры (M2Array<M2Texture>) (0x50 - 0x57) ----
    uint32_t num_textures;            // 0x50: Количество текстур.
    uint32_t offset_textures;         // 0x54: Смещение к определениям текстур.

    // ---- Прозрачность текстур (M2Array<M2TextureWeight>) (0x58 - 0x5F) ----
    uint32_t num_transparency;        // 0x58: Количество блоков данных о прозрачности.
    uint32_t offset_transparency;     // 0x5C: Смещение к данным о прозрачности.

    // ---- UV-анимации текстур (M2Array<M2TextureTransform>) (0x60 - 0x67) ----
    uint32_t num_texture_animations;  // 0x60: Количество блоков UV-анимации.
    uint32_t offset_texture_animations; // 0x64: Смещение к данным UV-анимации.

    // ---- Замена текстур (M2Array<uint16_t>) (0x68 - 0x6F) ----
    uint32_t num_texture_replace;     // 0x68: Количество заменяемых текстур (replacable_texture_lookup).
    uint32_t offset_texture_replace;  // 0x6C: Смещение к lookup-таблице заменяемых текстур.

    // ---- Материалы (Render Flags) (M2Array<M2Material>) (0x70 - 0x77) ----
    uint32_t num_materials;           // 0x70: Количество материалов (флагов рендеринга).
    uint32_t offset_materials;        // 0x74: Смещение к данным материалов.

    // ---- Таблицы поиска для рендеринга (Lookup Tables) (0x78 - 0x9F) ----
    uint32_t num_bone_combos;         // 0x78: M2Array<uint16_t> boneCombos.count (bone_lookup_table)
    uint32_t offset_bone_combos;      // 0x7C: M2Array<uint16_t> boneCombos.offset
    uint32_t num_texture_combos;      // 0x80: M2Array<uint16_t> textureCombos.count (texture_lookup_table)
    uint32_t offset_texture_combos;   // 0x84: M2Array<uint16_t> textureCombos.offset
    uint32_t num_tex_coord_combos;    // 0x88: M2Array<uint16_t> textureCoordCombos.count (tex_unit_lookup_table)
    uint32_t offset_tex_coord_combos; // 0x8C: M2Array<uint16_t> textureCoordCombos.offset
    uint32_t num_transparency_lookup; // 0x90: M2Array<uint16_t> textureWeightCombos.count (transparency_lookup_table)
    uint32_t offset_transparency_lookup;// 0x94: M2Array<uint16_t> textureWeightCombos.offset
    uint32_t num_tex_anim_lookup;     // 0x98: M2Array<uint16_t> textureTransformCombos.count (texture_transforms_lookup_table)
    uint32_t offset_tex_anim_lookup;  // 0x9C: M2Array<uint16_t> textureTransformCombos.offset

    // ---- Ограничивающие объемы для отображения (Display Bounding Volumes) (0xA0 - 0xBB) ----
    CAaBox   bounding_box;            // 0xA0 - 0xB7: (min_x,y,z, max_x,y,z) Ограничивающий параллелепипед для отображения.
    float    bounding_sphere_radius;  // 0xB8 - 0xBB: Радиус ограничивающей сферы для отображения.

    // ---- Ограничивающие объемы для коллизий (Collision Bounding Volumes) (0xBC - 0xD7) ----
    CAaBox   collision_box;           // 0xBC - 0xD3: Ограничивающий параллелепипед для коллизий.
    float    collision_sphere_radius; // 0xD4 - 0xD7: Радиус ограничивающей сферы для коллизий.

    // ---- Геометрия коллизий (M2Arrays) (0xD8 - 0xEF) ----
    uint32_t num_collision_indices;   // 0xD8: M2Array<uint16_t> collisionIndices.count
    uint32_t offset_collision_indices;// 0xDC: M2Array<uint16_t> collisionIndices.offset
    uint32_t num_collision_vertices;  // 0xE0: M2Array<C3Vector> collisionPositions.count
    uint32_t offset_collision_vertices;// 0xE4: M2Array<C3Vector> collisionPositions.offset
    uint32_t num_collision_normals;   // 0xE8: M2Array<C3Vector> collisionFaceNormals.count
    uint32_t offset_collision_normals;// 0xEC: M2Array<C3Vector> collisionFaceNormals.offset

    // ---- Прикрепления (Attachments) (M2Array<M2Attachment>) (0xF0 - 0xF7) ----
    uint32_t num_attachments;         // 0xF0: Количество точек прикрепления.
    uint32_t offset_attachments;      // 0xF4: Смещение к данным точек прикрепления.

    // ---- Таблица поиска прикреплений (M2Array<uint16_t>) (0xF8 - 0xFF) ----
    uint32_t num_attachment_lookup;   // 0xF8: Количество записей в таблице поиска прикреплений.
    uint32_t offset_attachment_lookup;// 0xFC: Смещение к таблице поиска прикреплений.

    // ---- События (Events) (M2Array<M2Event>) (0x100 - 0x107) ----
    uint32_t num_events;              // 0x100: Количество событий.
    uint32_t offset_events;           // 0x104: Смещение к данным событий.

    // 0x108 конец 264-байтного заголовка
}; 
```

### Ключевые наблюдения по структуре заголовка (на основе дампа ZulAmanTree02.m2)

* **`magic`**: `MD20`.
* **`version`**: `264`.
* **`length_model_name`**: `14`.
* **`offset_model_name`**: `304` (0x130) - имя модели (`ZulAmanTree02`) находится вне этого заголовка.
* **`num_textures` / `offset_textures`**: `3` / `20848` (0x5170) - нормальные значения, в отличие от предыдущих выводов парсера.
* **`num_transparency` / `offset_transparency`**: `1` / `21088` (0x5260) - также нормальные значения.
* **Bounding/Collision Geometry**: Смещения и структура полей, относящихся к `bounding_box`, `collision_box` и данным геометрии коллизий (`collisionIndices`, `collisionVertices`, `collisionNormals`), в дампе соответствуют смещениям, указанным на `wowdev.wiki` (начиная с 0xA0 для `bounding_box`, 0xBC для `collision_box`, 0xD8 для `collisionIndices.count` и т.д.).
* **Текстурные lookup-таблицы** (например, `num_bone_combos`, `num_texture_combos` и т.д., со смещений 0x78 до 0x9F) присутствуют в дампе с корректными значениями count/offset.
* Все поля до смещения 0x108 (включительно `offset_events`) заполнены осмысленными данными или нулями в предоставленном дампе, подтверждая размер заголовка 264 байта.

## 2. TODO: Анализ структур данных по смещениям

Следующим шагом будет детальный анализ и документирование структур данных, на которые указывают смещения из `M2_Header_WotLK`. К ним относятся:

* `M2Loop` (для Global Sequences)
* `M2Sequence` (Анимации)
* `M2CompBone` (Кости)
* `M2Vertex` (Вершины)
* `M2Color` (Цвета)
* `M2Texture` (Определения Текстур)
* `M2TextureWeight` (Прозрачность)
* `M2TextureTransform` (UV-анимации)
* `M2Material` (Материалы/Флаги рендеринга)
* Структуры для различных lookup-таблиц (если они не просто массивы `uint16_t`)
* `M2Attachment` (Прикрепления)
* `M2Event` (События)
* И особенно важно для NavMesh: формат данных для `collisionIndices` (массив `uint16_t`), `collisionPositions` (массив `C3Vector`) и `collisionFaceNormals` (массив `C3Vector`).

### 2.1 Геометрия для столкновений (Collision Geometry)

Данные для расчета столкновений (и, соответственно, для построения NavMesh) хранятся в нескольких связанных блоках, на которые указывают смещения в заголовке M2. Не все M2-файлы содержат эту геометрию; у многих декоративных объектов или визуальных эффектов эти поля могут быть нулевыми.

#### 2.1.1 `collisionIndices` (Индексы треугольников коллизий)

* **Поля в заголовке:**
  * `uint32_t num_collision_indices;` (0xD8): Количество индексов в массиве.
  * `uint32_t offset_collision_indices;` (0xDC): Смещение от начала файла к массиву индексов.
* **Структура данных:** Массив из `num_collision_indices` элементов типа `uint16_t`.
* **Назначение:** Каждые три последовательных индекса в этом массиве (`idx1, idx2, idx3`) определяют один треугольник, формирующий поверхность столкновения. Эти индексы ссылаются на вершины в массиве `collisionVertices`.
* **Пример:** Если `collisionIndices = [0, 1, 2, 2, 3, 0, ...]`, то первый треугольник состоит из вершин `collisionVertices[0]`, `collisionVertices[1]`, `collisionVertices[2]`, а второй – из `collisionVertices[2]`, `collisionVertices[3]`, `collisionVertices[0]`.
* **Анализ показал:**
  * Если `num_collision_indices > 0`, то оно всегда кратно трем.
  * Значения индексов являются 0-базированными и ссылаются на элементы в `collisionVertices`.
  * Многие M2-файлы, особенно визуальные эффекты или мелкие декорации, не имеют геометрии столкновений (`num_collision_indices = 0`).
* **Порядок обхода вершин (Winding Order):** Принято считать, что вершины треугольника (определяемые индексами `v0, v1, v2`) перечисляются в таком порядке (например, против часовой стрелки, если смотреть на лицевую сторону), чтобы векторное произведение `(v1-v0) x (v2-v0)` давало нормаль, направленную "наружу" от объекта. Это важно для последовательного вычисления нормалей, если они не предоставлены явно, и для определения "внутренней" и "внешней" стороны полигона.

#### 2.1.2 `collisionVertices` (Вершины коллизий)

* **Поля в заголовке:**
  * `uint32_t num_collision_vertices;` (0xE0): Количество вершин в массиве.
  * `uint32_t offset_collision_vertices;` (0xE4): Смещение от начала файла к массиву вершин.
* **Структура данных:** Массив из `num_collision_vertices` элементов типа `C3Vector`.

    ```cpp
    struct C3Vector {
        float x, y, z; // Координаты вершины
    };
    ```

* **Назначение:** Этот массив содержит фактические 3D-координаты вершин, которые образуют геометрию столкновений. Индексы из `collisionIndices` ссылаются на эти вершины. Эта геометрия обычно является упрощенной версией основной видимой геометрии модели.
* **Система координат:** Стандартная для WoW (Z - вверх).

#### 2.1.3 `collisionNormals` (Нормали граней коллизий)

* **Поля в заголовке:**
  * `uint32_t num_collision_normals;` (0xE8): Количество нормалей в массиве.
  * `uint32_t offset_collision_normals;` (0xEC): Смещение от начала файла к массиву нормалей.
* **Структура данных:** Массив из `num_collision_normals` элементов типа `C3Vector`.
* **Назначение:** Этот массив содержит нормали для каждой грани (треугольника) геометрии столкновений. Каждая нормаль `C3Vector` соответствует одному треугольнику, определенному в `collisionIndices`. Таким образом, `num_collision_normals` должно быть равно `num_collision_indices / 3`. Нормали важны для определения ориентации поверхности и могут использоваться в алгоритмах NavMesh, например, для определения проходимости склонов.
* **Примечание (Отсутствующие нормали):** В некоторых M2 файлах (особенно старых или для простых объектов) блок `collisionNormals` может отсутствовать (`num_collision_normals = 0` и `offset_collision_normals = 0`), даже если присутствует геометрия столкновений (`collisionIndices` и `collisionVertices`). В таких ситуациях нормали для каждого треугольника необходимо вычислять "на лету".
  Для треугольника, образованного вершинами `v0`, `v1`, `v2` (взятыми из `collisionVertices` согласно индексам из `collisionIndices`), нормаль `N` можно вычислить следующим образом:
    1. Определить два вектора-ребра, исходящие из одной вершины, например: `edge1 = v1 - v0` и `edge2 = v2 - v0`.
    2. Вычислить векторное произведение этих ребер: `N_unnormalized = cross_product(edge1, edge2)`. Порядок операндов в векторном произведении и, следовательно, направление результирующей нормали, зависит от принятого порядка обхода вершин (winding order).
    3. Нормализовать полученный вектор: `N = normalize(N_unnormalized)`.
  Корректный расчет нормалей критичен для алгоритмов NavMesh, определяющих проходимость (например, максимальный угол наклона) и ориентацию поверхности.

## 3. Ключевые данные M2 для построения NavMesh

Для построения навигационной сетки (NavMesh) из M2 модели, необходимы следующие основные компоненты из файла:

1. **`model_flags` (из заголовка `M2_Header_WotLK`):**
    * В частности, флаг `0x8 (Has_collision_volume)` является ключевым индикатором того, что модель должна содержать геометрию столкновений, предназначенную для физических взаимодействий. Модели без этого флага или без последующих данных коллизий могут быть проигнорированы при построении NavMesh или потребовать особого обращения.

2. **`collisionVertices` (Вершины коллизий):**
    * **Источник:** Массив `C3Vector` (float x, y, z), на который указывают `offset_collision_vertices` и `num_collision_vertices`.
    * **Назначение:** Содержит 3D-координаты вершин, образующих полигональную сетку (меш) столкновений.
    * **Система координат:** Локальная система координат модели (Z - вверх, стандарт для WoW).

3. **`collisionIndices` (Индексы треугольников коллизий):**
    * **Источник:** Массив `uint16_t`, на который указывают `offset_collision_indices` и `num_collision_indices`.
    * **Назначение:** Каждые три последовательных индекса (`i0, i1, i2`) в этом массиве определяют один треугольник. Эти индексы ссылаются на вершины в массиве `collisionVertices`. Например, треугольник состоит из `collisionVertices[i0]`, `collisionVertices[i1]`, `collisionVertices[i2]`.
    * **Количество треугольников:** Равно `num_collision_indices / 3`.
    * **Порядок обхода (Winding Order):** Важен для консистентного определения лицевой (проходимой) стороны треугольника и для правильного вычисления нормалей, если они не предоставлены.

4. **`collisionNormals` (Нормали граней коллизий):**
    * **Источник:** Массив `C3Vector`, на который указывают `offset_collision_normals` и `num_collision_normals`.
    * **Назначение:** Содержит векторы нормалей, по одному для каждого треугольника коллизии (`num_collision_normals` должно быть равно `num_collision_indices / 3`). Нормаль указывает "внешнее" направление поверхности треугольника.
    * **Важность для NavMesh:** Нормали используются для определения угла наклона поверхности (проходимость склонов), ориентации полигонов и других проверок геометрии.
    * **Если отсутствуют:** Нормали необходимо вычислять вручную для каждого треугольника на основе его вершин и их порядка обхода (см. примечание в разделе 2.1.3).

5. **`collision_box` и `collision_sphere_radius` (из заголовка `M2_Header_WotLK`):**
    * **Назначение:** Ограничивающие объемы для всей геометрии столкновений модели. Могут использоваться для:
        * Быстрого отсечения (culling) моделей, которые точно не пересекаются с областью построения NavMesh.
        * Грубой первоначальной проверки столкновений перед детализированным анализом треугольников.
    * Однако, для точного построения NavMesh необходима именно геометрия треугольников.

**Важно учитывать при построении глобального NavMesh:**

* **Локальное пространство:** Все данные геометрии столкновений в M2 файле (`collisionVertices`, `collisionNormals`, `collision_box`) определены в локальной системе координат модели.
* **Трансформация в мир:** Для использования в глобальной навигационной сетке (например, для всей игровой карты), эта локальная геометрия должна быть преобразована (транслирована, повернута, масштабирована) в мировые координаты. Информация о таком преобразовании для конкретного экземпляра M2 модели обычно содержится в файлах более высокого уровня, таких как ADT (для объектов на карте) или WMO (для объектов внутри WMO). Без этого преобразования NavMesh, построенный из M2, будет иметь смысл только для самой модели в ее исходной ориентации и масштабе.
