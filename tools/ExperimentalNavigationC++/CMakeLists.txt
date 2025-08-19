# --- Базовые настройки проекта ---
cmake_minimum_required(VERSION 3.22)
project(WoWNavigator LANGUAGES CXX)

# --- Интеграция с vcpkg (как в твоем примере) ---
# Убедись, что путь к vcpkg правильный.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/Dev/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

# --- Настройки компилятора и Qt ---
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# --- Поиск зависимостей ---
# Пока что нам нужен только Qt.
# vcpkg найдет его и предоставит CMake. 
find_package(Qt6 COMPONENTS Core Widgets REQUIRED)
find_package(VTK REQUIRED)
find_package(Eigen3 CONFIG REQUIRED)                 # Для математики

# --- Создание исполняемого файла ---
# Мы создаем один исполняемый файл "WoWNavigator"
# и перечисляем ВСЕ .cpp файлы, которые в него входят.
add_executable(WoWNavigator
    src/main.cpp
    src/shared/Logger.cpp
    src/gui/MainWindow.cpp
    src/gui/VtkWidget.cpp
    src/integration/MemoryManager.cpp
    src/integration/WoWController.cpp
    src/core/loader/ObjLoader.cpp
    src/core/generator/NavMeshGenerator.cpp
    src/core/generator/pipeline/Voxelizer.cpp
    src/core/pathfinder/Pathfinder.cpp
)

# --- Настройка путей для заголовочных файлов ---
# Эта команда говорит компилятору, что если он видит #include "gui/MainWindow.h",
# то искать его нужно начиная с папки src.
target_include_directories(WoWNavigator PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${VTK_INCLUDE_DIRS}
    ${VTK_QT_INCLUDE_DIRS}
)

# --- Подключение библиотек к нашему приложению ---
target_link_libraries(WoWNavigator PRIVATE
    Qt6::Core
    Qt6::Widgets
    ${VTK_LIBRARIES}
    Eigen3::Eigen       # Библиотека для векторов и матриц
)

# === Копирование плагина Qt (адаптировано из твоего примера) ===
add_custom_command(TARGET WoWNavigator POST_BUILD
    # Шаг 1: Создать директорию 'platforms' рядом с exe.
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:WoWNavigator>/platforms"

    # Шаг 2: Скопировать НУЖНЫЙ плагин (Debug или Release).
    # Используем более современный и надежный способ получения пути.
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "C:/Dev/vcpkg/installed/x64-windows/debug/Qt6/plugins/platforms/qwindowsd.dll"
    "$<TARGET_FILE_DIR:WoWNavigator>/platforms/"

    # Комментарий, который будет виден в логе сборки.
    COMMENT "Copying Qt platform plugin for $<CONFIG> configuration..."
)