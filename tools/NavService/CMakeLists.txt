cmake_minimum_required(VERSION 3.22)
project(NavService VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ------------------------------------------------------------------
# --- Зависимости из vcpkg ---
# ------------------------------------------------------------------
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/Dev/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

find_package(Qt6 COMPONENTS Core Widgets REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
enable_testing()

# ------------------------------------------------------------------
# --- Наша собственная версия Recast & Detour ---
# ------------------------------------------------------------------
add_library(RecastNav STATIC)
target_sources(RecastNav PRIVATE
    # --- Detour ---
    libs/recastnavigation/Detour/Source/DetourAlloc.cpp
    libs/recastnavigation/Detour/Source/DetourCommon.cpp
    libs/recastnavigation/Detour/Source/DetourNavMesh.cpp
    libs/recastnavigation/Detour/Source/DetourNavMeshBuilder.cpp
    libs/recastnavigation/Detour/Source/DetourNavMeshQuery.cpp
    libs/recastnavigation/Detour/Source/DetourNode.cpp
    libs/recastnavigation/Detour/Source/DetourAssert.cpp
    # --- Recast ---
    libs/recastnavigation/Recast/Source/Recast.cpp
    libs/recastnavigation/Recast/Source/RecastAlloc.cpp
    libs/recastnavigation/Recast/Source/RecastArea.cpp
    libs/recastnavigation/Recast/Source/RecastContour.cpp
    libs/recastnavigation/Recast/Source/RecastFilter.cpp
    libs/recastnavigation/Recast/Source/RecastLayers.cpp
    libs/recastnavigation/Recast/Source/RecastMesh.cpp
    libs/recastnavigation/Recast/Source/RecastMeshDetail.cpp
    libs/recastnavigation/Recast/Source/RecastRasterization.cpp
    libs/recastnavigation/Recast/Source/RecastRegion.cpp
    libs/recastnavigation/Recast/Source/RecastAssert.cpp
)
target_include_directories(RecastNav PUBLIC
    libs/recastnavigation/Detour/Include
    libs/recastnavigation/Recast/Include
)
target_compile_definitions(RecastNav PUBLIC DT_POLYREF64)

# ==================================================================
# === НАША ОСНОВНАЯ БИБЛИОТЕКА - NavServiceLib ===
# ==================================================================
# Создаем статическую библиотеку из всего нашего "полезного" кода
add_library(NavServiceLib STATIC
    src/NavServiceApp.cpp
    src/Communication/MessageHandler.cpp
    src/Utils/Logger.cpp
    src/Utils/CoordinateConverter.cpp
    src/Navigation/NavMeshManager.cpp
    src/Pathfinder/Pathfinder.cpp
    src/NamedPipeServer/NamedPipeServer.cpp
)

# Указываем пути к заголовочникам для нашей библиотеки
target_include_directories(NavServiceLib PUBLIC src)

# Линкуем зависимости для НАШЕЙ библиотеки
target_link_libraries(NavServiceLib PUBLIC
    RecastNav
    Qt6::Core
    Qt6::Widgets
    nlohmann_json::nlohmann_json
)

# ------------------------------------------------------------------
# --- Исполняемый файл NavService.exe ---
# ------------------------------------------------------------------
# Он теперь очень простой: просто main.cpp
add_executable(NavService src/main.cpp)

# Линкуем его с нашей основной библиотекой
target_link_libraries(NavService PRIVATE NavServiceLib)

if(WIN32)
    set_target_properties(NavService PROPERTIES WIN32_EXECUTABLE FALSE)
endif()

# ------------------------------------------------------------------
# --- Исполняемый файл тестового клиента ---
# ------------------------------------------------------------------
add_executable(test_client tests/test_client.cpp)
target_include_directories(test_client PRIVATE src)
target_link_libraries(test_client PRIVATE nlohmann_json::nlohmann_json)

# ------------------------------------------------------------------
# --- Исполняемый файл юнит-тестов ---
# ------------------------------------------------------------------
add_executable(unit_tests tests/test_navmesh_manager.cpp)

# Линкуем тесты с нашей основной библиотекой
target_link_libraries(unit_tests PRIVATE
    NavServiceLib
    GTest::gtest_main
)

include(GoogleTest)
gtest_add_tests(TARGET unit_tests)