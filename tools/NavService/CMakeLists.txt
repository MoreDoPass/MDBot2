cmake_minimum_required(VERSION 3.22)
project(NavService VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/Dev/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# --- Находим зависимости ---
find_package(Qt6 COMPONENTS Widgets Test REQUIRED)
find_package(recastnavigation CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED) # Находим Google Test

# --- Источники проекта ---
set(SOURCES
    src/main.cpp
    src/NavServiceApp.cpp
    src/Communication/MessageHandler.cpp
    src/Utils/Logger.cpp
    src/Utils/CoordinateConverter.cpp
    src/Navigation/NavMeshManager.cpp
    src/Pathfinder/Pathfinder.cpp
    src/NamedPipeServer/NamedPipeServer.cpp
)

set(HEADERS
    src/Utils/Logger.h
    src/Utils/CoordinateConverter.h
    src/Utils/Vector.h
    src/Navigation/NavMeshManager.h
    src/Pathfinder/Pathfinder.h
    src/NamedPipeServer/NamedPipeServer.h
)

# ==========================================================
# === Конфигурация для основного сервиса NavService ===
# ==========================================================
add_executable(NavService ${SOURCES} ${HEADERS})

target_compile_definitions(NavService PRIVATE DT_POLYREF64)
# Подключаем заголовочные файлы для NavService
target_include_directories(NavService PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Линкуем библиотеки для NavService
target_link_libraries(NavService PRIVATE
    Qt6::Core
    Qt6::Widgets
    RecastNavigation::Detour
    RecastNavigation::Recast
    nlohmann_json::nlohmann_json
)

# Настройки для Windows
if(WIN32)
    set_target_properties(NavService PROPERTIES WIN32_EXECUTABLE FALSE)
endif()

# ==========================================================
# === Конфигурация для тестового клиента Named Pipe ===
# ==========================================================
add_executable(test_client tests/test_client.cpp)


# Подключаем заголовочные файлы для test_client
target_include_directories(test_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Линкуем библиотеки для test_client
target_link_libraries(test_client PRIVATE
    nlohmann_json::nlohmann_json
)

# ==========================================================
# === Конфигурация для юнит-тестов (Google Test) ===
# ==========================================================
enable_testing()

# Создаем список исходников, необходимых для теста NavMeshManager.
# Мы не включаем main.cpp или NavServiceApp.cpp, но включаем сам менеджер
# и его зависимости (логгер, конвертер).
set(UNIT_TEST_SOURCES
    tests/test_navmesh_manager.cpp
    src/Navigation/NavMeshManager.cpp
    src/Utils/Logger.cpp
    src/Utils/CoordinateConverter.cpp
)

# Создаем исполняемый файл для наших тестов
add_executable(unit_tests ${UNIT_TEST_SOURCES})

target_compile_definitions(unit_tests PRIVATE DT_POLYREF64)
# Указываем, где лежат заголовочные файлы ("src", "src/Navigation" и т.д.)
target_include_directories(unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Линкуем библиотеки, необходимые для работы теста и тестируемого кода.
target_link_libraries(unit_tests PRIVATE
    GTest::gtest_main        # Сама библиотека Google Test с функцией main()
    Qt6::Core                # Нужно для QCoreApplication, QDir, QString и т.д.
    RecastNavigation::Detour # Нужно для dtNavMesh и других типов Detour
)

# Интегрируем тесты с системой CTest, чтобы их можно было запускать из IDE
include(GoogleTest)
gtest_add_tests(TARGET unit_tests)