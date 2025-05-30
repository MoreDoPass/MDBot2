cmake_minimum_required(VERSION 3.16)
project(MapEditor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Находим Qt
# Для Qt6, убедись что vcpkg правильно настроил пути или Qt установлен в системе
find_package(Qt6 REQUIRED COMPONENTS Widgets OpenGLWidgets)
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
# find_package(StormLib CONFIG REQUIRED) # <-- Комментируем, так как подключаем вручную

# --- Настройка для вручную собранной StormLib (такая же, как в NavMeshTool) ---
# Путь к директории с StormLib.h
set(MANUAL_STORM_LIB_INCLUDE_DIR "C:/Users/Adminka/source/repos/MDBot2/tools/NavMeshTool/stormlib/StormLib/src")
# Путь к директории с Debug .lib файлом StormLib
set(MANUAL_STORM_LIB_LIBRARY_DIR_DEBUG "C:/Users/Adminka/source/repos/MDBot2/tools/NavMeshTool/stormlib/StormLib/build_unicode/Debug")
# Ожидаем, что StormLib.lib был переименован в StormLibDUD.lib в этой директории
set(MANUAL_STORM_LIB_FILE_DEBUG "${MANUAL_STORM_LIB_LIBRARY_DIR_DEBUG}/StormLibDUD.lib")

# Так как у нас только Debug-версия StormLib, будем использовать её и для Release-сборки приложения (для теста)
set(MANUAL_STORM_LIB_FILE_RELEASE ${MANUAL_STORM_LIB_FILE_DEBUG})
# --- Конец настройки для StormLib ---

# Исходные файлы
set(PROJECT_SOURCES
    src/main.cpp
    src/gui/MainWindow.cpp
    src/gui/MainWindow.h
    src/gui/Map3DView/Map3DView.cpp # Новый путь
    src/gui/Map3DView/Map3DView.h   # Новый путь
    src/gui/Map3DView/Camera/Camera.h
    src/gui/Map3DView/Camera/Camera.cpp
    src/gui/ProcessSelectionDialog/ProcessSelectionDialog.h
    src/gui/ProcessSelectionDialog/ProcessSelectionDialog.cpp
    src/gui/Map3DView/Renderers/WaypointRenderer.h
    src/gui/Map3DView/Renderers/WaypointRenderer.cpp
    src/gui/Map3DView/Renderers/ConnectionLineRenderer.h
    src/gui/Map3DView/Renderers/ConnectionLineRenderer.cpp
    src/gui/Map3DView/Renderers/ObstacleRenderer.h
    src/gui/Map3DView/Renderers/ObstacleRenderer.cpp
    src/gui/Map3DView/Renderers/PlayerMarkerRenderer.h
    src/gui/Map3DView/Renderers/PlayerMarkerRenderer.cpp
    src/gui/Map3DView/Renderers/ObstaclePointRenderer.h
    src/gui/Map3DView/Renderers/ObstaclePointRenderer.cpp
    src/gui/Map3DView/Renderers/ObstacleLineRenderer.h
    src/gui/Map3DView/Renderers/ObstacleLineRenderer.cpp
    src/gui/MpqManager/MpqManagerWidget.h
    src/gui/MpqManager/MpqManagerWidget.cpp
    src/core/Player/PlayerDataSource.h
    src/core/Player/PlayerDataSource.cpp
    src/core/Player/EditorPlayerPointerHook.h
    src/core/Player/EditorPlayerPointerHook.cpp
    src/core/MapData/Waypoint.h
    src/core/MapData/Waypoint.cpp
    src/core/MapData/MapData.h
    src/core/MapData/MapDataManager.h
    src/core/MapData/MapDataManager.cpp
    src/core/LoS/LineOfSight.h
    src/core/LoS/LineOfSight.cpp
    src/core/Pathfinding/AStar.h
    src/core/Pathfinding/AStar.cpp
    src/core/Pathfinding/BugPathfinder.h
    src/core/Pathfinding/BugPathfinder.cpp
    src/core/Voxels/VoxelMap.h
    src/core/Voxels/VoxelMap.cpp
    src/core/Voxels/VoxelMapManager.h
    src/core/Voxels/VoxelMapManager.cpp
    src/core/WoWFileParser/MpqManager.h
    src/core/WoWFileParser/MpqManager.cpp
)

# Ресурсные файлы (добавляем наш .qrc)
set(PROJECT_RESOURCES
    resources.qrc # Путь относительно этого CMakeLists.txt
)

# Исходные файлы GUI
set(MAP_EDITOR_GUI_SOURCES
    src/gui/MainWindow.h
    src/gui/MainWindow.cpp
    src/gui/Map3DView/Map3DView.h # Новый путь
    src/gui/Map3DView/Map3DView.cpp # Новый путь
    src/gui/Map3DView/Camera/Camera.h
    src/gui/Map3DView/Camera/Camera.cpp
    src/gui/ProcessSelectionDialog/ProcessSelectionDialog.h
    src/gui/ProcessSelectionDialog/ProcessSelectionDialog.cpp
)

# Если будут .ui файлы, их нужно будет добавить сюда или обрабатывать отдельно
# set(UI_FILES
#     src/gui/mainwindow.ui
# )
# qt_wrap_ui(PROJECT_SOURCES ${UI_FILES})

# Исполняемый файл
add_executable(MapEditor ${PROJECT_SOURCES} ${PROJECT_RESOURCES})

# Линковка с Qt
# Для Qt6:
target_link_libraries(MapEditor PRIVATE 
    Qt6::Widgets 
    Qt6::OpenGLWidgets
    Core_MemoryManager
    Core_ProcessManager
    Core_HookManager
    # StormLib::storm # <-- Комментируем, так как подключаем вручную
    debug ${MANUAL_STORM_LIB_FILE_DEBUG}        # <--- Линкуем Debug StormLib
    optimized ${MANUAL_STORM_LIB_FILE_RELEASE}  # <--- Линкуем Release StormLib (используем Debug-версию для теста)
    ZLIB::ZLIB # Добавлено ZLIB и BZip2 как зависимости StormLib
    BZip2::BZip2
)
# Для Qt5, измени на:
# target_link_libraries(MapEditor PRIVATE Qt5::Widgets Qt5::OpenGLWidgets)

# Директории для заголовочных файлов
# src/ уже должна быть доступна через относительные пути в PROJECT_SOURCES
# но если есть другие поддиректории в src/, их можно добавить так:
target_include_directories(MapEditor PRIVATE
    src # Позволяет использовать #include "gui/MainWindow.h" из main.cpp
    ${MANUAL_STORM_LIB_INCLUDE_DIR} # <--- Добавляем путь к заголовкам StormLib
)

# Если ты используешь vcpkg и CMakeLists.txt находится в поддиректории,
# убедись, что CMAKE_TOOLCHAIN_FILE из vcpkg передается при конфигурации этого подпроекта,
# или что корневой CMakeLists.txt правильно настраивает vcpkg.

# Пример для vcpkg, если этот CMakeLists.txt корневой или настраивается отдельно:
# if(DEFINED CMAKE_TOOLCHAIN_FILE)
#   include(${CMAKE_TOOLCHAIN_FILE})
# endif()

# Напоминание о логировании из правил:
# - Используй систему логирования через Qt QLoggingCategory для всех важных событий, ошибок и действий.

# --- Начало секции копирования зависимостей Qt (vcpkg x86 - ручное копирование) ---

if(WIN32) # Условие теперь только на WIN32
    message(STATUS "DEBUG_DEPLOY: WIN32 detected. Setting up potential deployment commands.")

    set(VCPKG_X86_BIN_DIR_DEBUG "C:/Dev/    vcpkg/installed/x86-windows/debug/bin")
    set(VCPKG_X86_PLUGINS_DIR_DEBUG "C:/Dev/vcpkg/installed/x86-windows/debug/Qt6/plugins")
    
    # Для Release (если понадобится, можно будет добавить аналогичные переменные)
    # set(VCPKG_X86_BIN_DIR_RELEASE "C:/Dev/vcpkg/installed/x86-windows/bin")
    # set(VCPKG_X86_PLUGINS_DIR_RELEASE "C:/Dev/vcpkg/installed/x86-windows/Qt6/plugins")

    # Используем $<CONFIG> генераторное выражение для путей к файлам и в условии команды
    # $<CONFIG:Debug> будет истинно только если текущая конфигурация сборки - Debug

    # 1. Копирование qwindowsd.dll для Debug
    set(PLATFORM_PLUGIN_SOURCE_DEBUG "${VCPKG_X86_PLUGINS_DIR_DEBUG}/platforms/qwindowsd.dll")
    
    # Целевая директория для плагинов, $<CONFIG> используется для Debug/Release подпапки
    set(PLATFORM_PLUGIN_DEST_DIR_BASE "$<TARGET_FILE_DIR:MapEditor>/platforms") 

    message(STATUS "DEBUG_DEPLOY: PLATFORM_PLUGIN_SOURCE_DEBUG (qwindowsd.dll) = ${PLATFORM_PLUGIN_SOURCE_DEBUG}")

    if(EXISTS "${PLATFORM_PLUGIN_SOURCE_DEBUG}")
        message(STATUS "DEBUG_DEPLOY: qwindowsd.dll (Debug) FOUND at ${PLATFORM_PLUGIN_SOURCE_DEBUG}. Adding copy command for Debug config.")
        add_custom_command(TARGET MapEditor POST_BUILD
            # Выполняем команду только если конфигурация Debug
            COMMAND $<$<CONFIG:Debug>:${CMAKE_COMMAND}> -E make_directory "${PLATFORM_PLUGIN_DEST_DIR_BASE}"
            COMMAND $<$<CONFIG:Debug>:${CMAKE_COMMAND}> -E copy_if_different
                "${PLATFORM_PLUGIN_SOURCE_DEBUG}"
                "${PLATFORM_PLUGIN_DEST_DIR_BASE}/" 
            COMMENT "Copying qwindowsd.dll for Debug config if active"
            VERBATIM
        )
    else()
        message(WARNING "DEBUG_DEPLOY: qwindowsd.dll (Debug) NOT FOUND at ${PLATFORM_PLUGIN_SOURCE_DEBUG}.")
    endif()

    # 2. Копирование основных runtime библиотек Qt для Debug
    set(QT_DEBUG_RUNTIME_DLLS
        "${VCPKG_X86_BIN_DIR_DEBUG}/Qt6Cored.dll"
        "${VCPKG_X86_BIN_DIR_DEBUG}/Qt6Guid.dll"
        "${VCPKG_X86_BIN_DIR_DEBUG}/Qt6Widgetsd.dll"
        "${VCPKG_X86_BIN_DIR_DEBUG}/Qt6OpenGLd.dll"
        "${VCPKG_X86_BIN_DIR_DEBUG}/Qt6OpenGLWidgetsd.dll"
    )

    message(STATUS "DEBUG_DEPLOY: Setting up runtime DLL copy commands for Debug config...")
    foreach(QT_DLL_PATH_VAR ${QT_DEBUG_RUNTIME_DLLS})
        message(STATUS "DEBUG_DEPLOY: Checking DLL for Debug: ${QT_DLL_PATH_VAR}")
        if(EXISTS "${QT_DLL_PATH_VAR}")
            message(STATUS "DEBUG_DEPLOY: DLL (Debug) FOUND: ${QT_DLL_PATH_VAR}. Adding copy command for Debug config.")
            add_custom_command(TARGET MapEditor POST_BUILD
                COMMAND $<$<CONFIG:Debug>:${CMAKE_COMMAND}> -E copy_if_different
                    "${QT_DLL_PATH_VAR}"
                    "$<TARGET_FILE_DIR:MapEditor>/" # Копируем рядом с exe
                COMMENT "Copying ${QT_DLL_PATH_VAR} for Debug config if active"
                VERBATIM
            )
        else()
            message(WARNING "DEBUG_DEPLOY: Required Qt DLL (Debug) NOT FOUND: ${QT_DLL_PATH_VAR}.")
        endif()
    endforeach()
else()
    message(STATUS "DEBUG_DEPLOY: Not a WIN32 build, skipping Qt deployment commands.")
endif()

# --- Конец секции копирования зависимостей Qt (vcpkg x86 - ручное копирование) ---

install(TARGETS MapEditor DESTINATION bin) # Куда устанавливать, если потребуется

# --- Тест для StormLib --- (УДАЛЯЕМ ЭТУ СЕКЦИЮ)
# add_executable(StormLibTest tests/stormlib_test.cpp)
# target_link_libraries(StormLibTest PRIVATE StormLib::storm)

# Опционально: если вы хотите, чтобы тест собирался только в Debug конфигурации (УДАЛЯЕМ ЭТУ СЕКЦИЮ)
# if(CMAKE_BUILD_TYPE STREQUAL "Debug")
#     add_executable(StormLibTest ../../tests/stormlib_test.cpp)
#     target_link_libraries(StormLibTest PRIVATE StormLib::storm)
#     message(STATUS "StormLibTest executable will be built (Debug config).")
# else()
#     message(STATUS "StormLibTest executable will NOT be built (Not a Debug config).")
# endif()