cmake_minimum_required(VERSION 3.16)
project(NavMeshTool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # Полезно для Windows, если будете делать библиотеки DLL из частей проекта
set(CMAKE_AUTOMOC ON) # Для Qt Meta-Object Compiler

# Поиск необходимых пакетов
find_package(Qt6 COMPONENTS Core REQUIRED)
# find_package(StormLib CONFIG REQUIRED) # Не используем, подключаем вручную
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)

# --- Настройка для вручную собранной StormLib ---
# Путь к директории с StormLib.h и другими заголовочными файлами StormLib
set(STORM_LIB_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/stormlib/StormLib/src")

# Путь к скомпилированному файлу StormLib.lib (Release, Unicode, x86)
set(STORM_LIB_LIBRARY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/stormlib/StormLib/build/Release/StormLib.lib") # Убедись, что этот путь верен!

# Проверяем, существует ли файл библиотеки StormLib
if(NOT EXISTS "${STORM_LIB_LIBRARY_FILE}")
    message(FATAL_ERROR "Файл библиотеки StormLib не найден по пути: ${STORM_LIB_LIBRARY_FILE}. Пожалуйста, проверьте путь и соберите StormLib.")
else()
    message(STATUS "Файл библиотеки StormLib найден: ${STORM_LIB_LIBRARY_FILE}")
endif()
# --- Конец настройки для StormLib ---

# Список исходных файлов для основного приложения
set(NAV_MESH_TOOL_APP_SOURCES
    src/main.cpp
    src/Core/MpqManager/MpqManager.cpp
)

# Создаем исполняемый файл приложения
add_executable(NavMeshTool_app ${NAV_MESH_TOOL_APP_SOURCES})

# Указываем пути для поиска заголовочных файлов для приложения
target_include_directories(NavMeshTool_app PRIVATE
    src  # Позволит писать #include "Core/MpqManager/MpqManager.h" и т.п.
    ${Qt6_Core_INCLUDE_DIRS} # Добавляем пути к заголовкам Qt Core
    ${STORM_LIB_INCLUDE_DIR} # <--- Путь к заголовкам StormLib
    # Если у вас будут заголовочные файлы в других местах, добавьте их сюда
    # например, ${PROJECT_SOURCE_DIR}/include
)

# Устанавливаем определения для Unicode
target_compile_definitions(NavMeshTool_app PRIVATE UNICODE _UNICODE)

# Подключаем библиотеки к приложению
target_link_libraries(NavMeshTool_app PRIVATE
    Qt::Core # Связываем с Qt Core
    "${STORM_LIB_LIBRARY_FILE}" # <--- Явно линкуем наш StormLib.lib
    ZLIB::ZLIB
    BZip2::BZip2
)

# Если вы будете использовать StormLib, и он собирается через vcpkg или как часть вашего проекта,
# вам нужно будет настроить find_package(StormLib REQUIRED) и связать его.
# Пример для vcpkg (если StormLib установлен через vcpkg и интегрирован с CMake проектом):
# find_package(StormLib CONFIG REQUIRED)
# target_link_libraries(NavMeshTool_app PRIVATE StormLib::StormLib)

# Для начала, этого должно быть достаточно.
# Позже, когда вы добавите больше исходных файлов или зависимостей,
# этот файл нужно будет расширить.

# Установка основного приложения
install(TARGETS NavMeshTool_app DESTINATION bin) # Копирует .exe в подпапку bin при установке

# --- Тест для StormLib в рамках NavMeshTool ---
# Проверяем, существует ли тестовый файл
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/stormlib_test.cpp")
    set(STORM_LIB_TEST_SOURCES
        tests/stormlib_test.cpp
    )
    add_executable(NavMesh_StormLibTest ${STORM_LIB_TEST_SOURCES})
    
    target_include_directories(NavMesh_StormLibTest PRIVATE
        src # Если тесту нужны другие заголовки из NavMeshTool
        ${STORM_LIB_INCLUDE_DIR} # <--- Путь к заголовкам StormLib
        # ${Qt6_Core_INCLUDE_DIRS} # Раскомментируй, если тест использует Qt напрямую
    )

    # Устанавливаем определения для Unicode для теста
    target_compile_definitions(NavMesh_StormLibTest PRIVATE UNICODE _UNICODE)

    target_link_libraries(NavMesh_StormLibTest PRIVATE
        # Qt::Core # Раскомментируй, если тест использует Qt напрямую
        # StormLib::storm # <-- Комментируем
        "${STORM_LIB_LIBRARY_FILE}" # <--- Явно линкуем наш StormLib.lib
        ZLIB::ZLIB
        BZip2::BZip2
    )
    message(STATUS "NavMesh_StormLibTest executable will be built using StormLib: ${STORM_LIB_LIBRARY_FILE}")
else()
    message(WARNING "StormLib test file not found at ${CMAKE_CURRENT_SOURCE_DIR}/tests/stormlib_test.cpp. Test target will not be created.")
endif() 