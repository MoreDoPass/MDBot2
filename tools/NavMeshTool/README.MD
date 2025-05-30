# NavMeshTool - Заметки по интеграции StormLib

Этот документ описывает ключевые моменты, проблемы и решения, возникшие при интеграции библиотеки StormLib в проект NavMeshTool с использованием CMake.

## 1. Подключение StormLib и управление зависимостями

Изначально StormLib подключалась вручную в `CMakeLists.txt` проекта `NavMeshTool` путем прямого указания пути к заголовочным файлам и скомпилированной `.lib` библиотеке.

```cmake
# Пример из CMakeLists.txt NavMeshTool
# Путь к директории с StormLib.h и другими заголовочными файлами StormLib
set(STORM_LIB_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/stormlib/StormLib/src")
# Путь к скомпилированному файлу StormLib.lib
set(STORM_LIB_LIBRARY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/stormlib/StormLib/build/Release/StormLib.lib") # Изначально указывал только на Release

# ...
target_include_directories(NavMeshTool_app PRIVATE ${STORM_LIB_INCLUDE_DIR})
target_link_libraries(NavMeshTool_app PRIVATE "${STORM_LIB_LIBRARY_FILE}")
```

**Проблема:** Жестко заданный путь к Release-версии библиотеки (`StormLib.lib`) означал, что Debug-сборки `NavMeshTool` также линковались с Release-версией StormLib. Это не рекомендуется из-за возможных конфликтов CRT (C Runtime Library) и отсутствия отладочной информации.

**Решение (рекомендуемое, но не реализованное в полной мере на момент написания):**
В идеале, CMake-скрипты StormLib должны быть настроены для сборки как Debug, так и Release версий (например, `stormd.lib` и `storm.lib`). Затем `CMakeLists.txt` основного проекта должен выбирать соответствующую версию библиотеки в зависимости от конфигурации сборки (`CMAKE_BUILD_TYPE`).

```cmake
# Пример концепции для CMakeLists.txt NavMeshTool (если есть разные версии StormLib)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(STORM_LIB_LIBRARY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/stormlib/StormLib/build/Debug/stormd.lib")
else()
    set(STORM_LIB_LIBRARY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/stormlib/StormLib/build/Release/storm.lib")
endif()
```

На текущий момент, так как собрана только Release-версия StormLib, используется она.

## 2. Директивы `#pragma comment(lib, ...)` и конфликт с CMake

Файл `StormLib.h` (оригинальный) содержит директивы препроцессора `#pragma comment(lib, "StormLibXYZ.lib")`. Эти директивы являются специфичными для компилятора MSVC и указывают компоновщику, какие файлы библиотек нужно подключить. Имя библиотеки (`StormLibXYZ.lib`) в этих прагмах зависит от конфигурации сборки (Debug/Release, ANSI/Unicode, Static/DLL CRT).

**Проблема:**
Когда `NavMeshTool` собирался в конфигурации Debug/Unicode/DLL-CRT, соответствующая прагма пыталась подключить библиотеку с именем вроде `StormLibDUD.lib`. Однако:

1. Собранная нами библиотека StormLib (через её собственный CMake) могла называться просто `storm.lib` или `StormLib.lib`.
2. CMake в `NavMeshTool` уже явно указывал компоновщику, какую библиотеку линковать (например, `Release/StormLib.lib`).

Это приводило к тому, что компоновщик получал два указания: одно от CMake (на существующую `StormLib.lib`) и одно от прагмы (на несуществующую `StormLibDUD.lib`), что вызывало ошибку `LNK1104: не удается открыть файл "StormLibDUD.lib"`.

**Решение:**
Строки с `#pragma comment(lib, ...)` в файле `tools/NavMeshTool/stormlib/StormLib/src/StormLib.h` были закомментированы. Это позволило передать полный контроль над процессом линковки системе сборки CMake, которая уже корректно указывала на имеющийся файл библиотеки.

## 3. Пути к файлам внутри MPQ-архивов: Регистр и Слеши

После решения проблем с линковкой возникла следующая сложность: функции StormLib (`SFileHasFile`, `SFileOpenFileEx` и др.) не могли найти файлы внутри MPQ-архива, возвращая ошибку `2` (ERROR_FILE_NOT_FOUND).

**Проблема:**
Предполагаемые пути к файлам (например, `World/Maps/Azeroth/Azeroth_32_25.adt`) не совпадали с тем, как они реально хранятся в MPQ-архиве.

**Решение и Ключевые Моменты:**

1. **Извлечение `(listfile)`:** Внутренний файл MPQ-архива, называемый `(listfile)`, содержит список всех файлов и их точных путей внутри архива. Успешное чтение и извлечение этого файла стало ключом к диагностике.
2. **Чувствительность к регистру:** Пути внутри MPQ, как показал `(listfile)`, чувствительны к регистру. Например, путь `world\maps\...` (с маленькой `w`) является правильным, в то время как `World/maps/...` (с большой `W`) не будет найден.
3. **Разделители пути (слеши):** `(listfile)` показал, что в архивах используются обратные слеши (`\`) в качестве разделителей пути. Хотя StormLib может быть гибкой в этом отношении, использование формата из `(listfile)` является наиболее надежным подходом.
    * При указании таких путей в строковых литералах C++, обратный слеш необходимо экранировать: `"world\\maps\\..."`.

**Пример правильного пути (согласно `(listfile)`):** `world\maps\azjolarena\azjolarena_31_31.adt`

## 4. Кодировки: ANSI, Unicode и Пути к файлам

* **Пути к MPQ-архивам (внешние пути):** Функции StormLib, такие как `SFileOpenArchive`, которые принимают пути к файлам MPQ в файловой системе, ожидают их в формате `const TCHAR*`. В Unicode-сборке Windows это `const wchar_t*`. Поэтому строки `std::string` (обычно UTF-8 или ANSI) нужно конвертировать в `std::wstring` перед передачей в эти функции. Это было реализовано в `MpqManager` с помощью `std::wstring_convert`.

    ```cpp
    // MpqManager.cpp
    std::wstring wArchivePath = stringToWstring(archivePath); // stringToWstring использует codecvt_utf8_utf16
    SFileOpenArchive(wArchivePath.c_str(), 0, 0, &hMpq_);
    ```

* **Пути внутри MPQ-архивов:** Функции StormLib, работающие с файлами внутри архива (например, `SFileHasFile`, `SFileOpenFileEx`), принимают пути как `const char*`. Предполагается, что эти пути соответствуют записям в `(listfile)`. Исторически, `(listfile)` часто содержал пути в кодировке ANSI (зависящей от локали системы, на которой MPQ создавался). Современные версии StormLib и MPQ могут лучше работать с UTF-8, но важно, чтобы строка, передаваемая как `const char*`, соответствовала тому, что ожидает StormLib для данного конкретного архива и его `(listfile)`. В нашем случае, передача `std::string::c_str()` после коррекции регистра и слешей сработала.

* **Макросы `UNICODE` и `_UNICODE`:** Для корректной работы с Windows API в режиме Unicode (использование `wchar_t`, вызов `W` версий функций API, таких как `CreateFileW` вместо `CreateFileA`), в проекте должны быть определены препроцессорные макросы `UNICODE` и `_UNICODE`. Это было сделано в `CMakeLists.txt` для `NavMeshTool_app`:

    ```cmake
    target_compile_definitions(NavMeshTool_app PRIVATE UNICODE _UNICODE)
    ```

## 5. Проблема `ERROR_SHARING_VIOLATION` (Ошибка 32)

При попытке открыть MPQ-архив возникала ошибка `32` (`ERROR_SHARING_VIOLATION`).

**Проблема:** Файл MPQ был заблокирован другим процессом (например, запущенной игрой WoW или другим экземпляром приложения).

**Решение:** Убедиться, что никакие другие процессы не используют данный MPQ-файл эксклюзивно. Закрыть игру, другие утилиты для MPQ и т.д.

## Итог

Успешная работа с MPQ-архивами через StormLib требует внимательности к деталям:

* Правильная конфигурация сборки и линковки самой StormLib и приложения.
* Аккуратное управление зависимостями, особенно при использовании CMake совместно с механизмами вроде `#pragma comment(lib, ...)`.
* Точное соответствие путей файлов внутри архива (регистр, слеши) записям в `(listfile)`.
* Правильная обработка кодировок строк для путей файловой системы и путей внутри архива.
* Учет возможных блокировок файлов другими процессами.

Надеюсь, эти заметки будут полезны!
