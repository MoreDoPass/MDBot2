cmake_minimum_required(VERSION 3.22)
project(MDBot2 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Настройки для vcpkg
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/Dev/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# --- Поиск всех зависимостей ---
find_package(Qt6 COMPONENTS Widgets Test REQUIRED)
find_package(capstone CONFIG REQUIRED)
find_package(recastnavigation CONFIG REQUIRED)

# --- Подключаем наши core-библиотеки ---
# Эта команда заставит CMake зайти в папку src/core и выполнить CMakeLists.txt оттуда.
# После этого все цели (Core_MemoryManager, Core_Teleport и т.д.) будут доступны здесь.
add_subdirectory(src/core)

add_subdirectory(tools/MDHack)

# --- Создаем основной исполняемый файл ---
# Здесь мы перечисляем ТОЛЬКО те cpp-файлы, которые не входят ни в одну из core-библиотек.
# В основном это файлы из папок gui/ и некоторые общие.
add_executable(MDBot2
    src/main.cpp
    src/gui/MainWindow.cpp
    src/gui/ProcessManager/ProcessListDialog.cpp
    src/core/Logging/Logging.cpp
    src/gui/Logging/LogWindow.cpp
    src/core/Bot/Bot.cpp
    src/gui/Bot/BotWidget.cpp
    src/gui/Bot/CharacterWidget/CharacterWidget.cpp
    src/gui/Bot/MainWidget/MainWidget.cpp
    src/core/Bot/Movement/MovementManager.cpp
    src/core/Bot/Movement/CtM/CtM.cpp
    src/core/Bot/Movement/CtM/CtMEnablerHook.cpp
    src/core/Bot/Movement/Pathfinder/Pathfinder.cpp
)

# --- Линкуем MDBot2 со всеми нужными библиотеками ---
target_link_libraries(MDBot2 PRIVATE 
    # Внешние библиотеки
    Qt6::Widgets 
    capstone::capstone 
    RecastNavigation::Detour
    
    # Наши внутренние core-библиотеки
    Core_MemoryManager
    Core_ProcessManager
    Core_HookManager
    Core_Navigation
    Core_Teleport # <-- ДОБАВЛЕНА НОВАЯ БИБЛИОТЕКА
    Core_Character
    Core_GameObject
)

# Указываем, где искать заголовочные файлы
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
# (Раздел с тестами оставляем без изменений, он корректен)
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

add_executable(test_InlineHook
    tests/test_InlineHook.cpp
)
target_include_directories(test_InlineHook PRIVATE
    src
    $<TARGET_PROPERTY:capstone::capstone,INTERFACE_INCLUDE_DIRECTORIES>
)
target_link_libraries(test_InlineHook PRIVATE 
    Qt6::Core 
    Qt6::Test 
    capstone::capstone
    Core_MemoryManager
    Core_ProcessManager
    Core_HookManager # Хук-тесту нужен Core_HookManager
)
add_test(NAME InlineHookTest COMMAND test_InlineHook)

add_executable(test_CtM
    tests/test_CtM.cpp
    src/core/Bot/Movement/CtM/CtMEnablerHook.cpp # Предполагается, что CtMEnablerHook не часть Core_HookManager
    src/core/Bot/Movement/CtM/CtM.cpp
)
target_include_directories(test_CtM PRIVATE
    src
)
target_link_libraries(test_CtM PRIVATE 
    Qt6::Core 
    Qt6::Test 
    capstone::capstone
    Core_MemoryManager
    Core_ProcessManager
    Core_HookManager # Тесту CtM тоже могут понадобиться хуки
)
add_test(NAME CtMTest COMMAND test_CtM)