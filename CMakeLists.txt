cmake_minimum_required(VERSION 3.22)
project(MDBot2 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/Dev/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)

find_package(Qt6 COMPONENTS Widgets Test REQUIRED)

# Добавляем Capstone через vcpkg
find_package(capstone CONFIG REQUIRED)

# Добавляем recastnavigation через vcpkg
find_package(recastnavigation CONFIG REQUIRED)

# Подключаем core-библиотеки
add_subdirectory(src/core)

# Подключаем Сборку Navmesh - ЭТО УБИРАЕМ, Т.К. ЭТО ОТДЕЛЬНЫЙ ПРОЕКТ С ДРУГИМИ ТРЕБОВАНИЯМИ К СБОРКЕ (x64)
# add_subdirectory(tools/NavMeshTool)

add_executable(MDBot2
    src/main.cpp
    src/gui/MainWindow.cpp
    src/gui/ProcessManager/ProcessListDialog.cpp
    src/core/Logging/Logging.cpp
    src/gui/Logging/LogWindow.cpp
    src/core/Bot/Bot.cpp
    src/gui/Bot/BotWidget.cpp
    src/core/HookManager/HookManager.cpp
    src/core/HookManager/Hook/InlineHook/InlineHook.cpp
    src/core/Bot/Character/Character.cpp
    src/core/Bot/Character/CharacterHook.cpp
    src/gui/Bot/CharacterWidget/CharacterWidget.cpp
    src/gui/Bot/MainWidget/MainWidget.cpp
    src/core/Bot/Movement/MovementManager.cpp
    src/core/Bot/Movement/CtM/CtM.cpp
    src/core/Bot/Movement/CtM/CtMEnablerHook.cpp
    src/core/Bot/Movement/Pathfinder/Pathfinder.cpp
)

target_link_libraries(MDBot2 PRIVATE 
    Qt6::Widgets 
    capstone::capstone 
    RecastNavigation::Detour
    Core_MemoryManager
    Core_ProcessManager
    Core_HookManager
    Core_Navigation
)

target_include_directories(MDBot2 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# --- Копирование плагина платформы Qt (qwindowsd.dll) для Debug-сборки ---
add_custom_command(TARGET MDBot2 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:MDBot2>/platforms"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "C:/Dev/vcpkg/installed/x86-windows/debug/Qt6/plugins/platforms/qwindowsd.dll"
        "$<TARGET_FILE_DIR:MDBot2>/platforms/"
)

# --- Тесты ---
enable_testing()
add_executable(test_MemoryManager
    tests/test_MemoryManager.cpp
)
target_include_directories(test_MemoryManager PRIVATE
    src
)
target_link_libraries(test_MemoryManager PRIVATE 
    Qt6::Core 
    Qt6::Test
    Core_MemoryManager
    Core_ProcessManager
)
add_test(NAME MemoryManagerTest COMMAND test_MemoryManager)

# Добавляем тест для InlineHook
add_executable(test_InlineHook
    tests/test_InlineHook.cpp
    src/core/HookManager/Hook/InlineHook/InlineHook.cpp
)
target_include_directories(test_InlineHook PRIVATE
    src/core/HookManager/Hook/InlineHook
    src
    $<TARGET_PROPERTY:capstone::capstone,INTERFACE_INCLUDE_DIRECTORIES>
)
target_link_libraries(test_InlineHook PRIVATE 
    Qt6::Core 
    Qt6::Test 
    capstone::capstone
    Core_MemoryManager
    Core_ProcessManager
)
add_test(NAME InlineHookTest COMMAND test_InlineHook)

# Добавляем тест для CtM
add_executable(test_CtM
    tests/test_CtM.cpp
    src/core/Bot/Character/CharacterHook.cpp
    src/core/Bot/Movement/CtM/CtMEnablerHook.cpp
    src/core/Bot/Movement/CtM/CtM.cpp
    src/core/HookManager/Hook/InlineHook/InlineHook.cpp
)
target_include_directories(test_CtM PRIVATE
    src/core/Bot/Character
    src/core/Bot/Movement/CtM
    src/core/Bot/Movement
    src
)
target_link_libraries(test_CtM PRIVATE 
    Qt6::Core 
    Qt6::Test 
    capstone::capstone
    Core_MemoryManager
    Core_ProcessManager
)
add_test(NAME CtMTest COMMAND test_CtM)