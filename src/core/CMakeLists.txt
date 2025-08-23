cmake_minimum_required(VERSION 3.16)
project(MDBot2CoreLibs LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)

# Базовая директория для поиска всех core-заголовков.
# ${CMAKE_CURRENT_SOURCE_DIR} - это .../src/core, нам нужен уровень выше.
set(CORE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

# --- Библиотека MemoryManager ---
add_library(Core_MemoryManager STATIC
    MemoryManager/MemoryManager.cpp
)
target_include_directories(Core_MemoryManager PUBLIC
    ${CORE_INCLUDE_DIR}
)
target_link_libraries(Core_MemoryManager PUBLIC Qt6::Core)


# --- Библиотека ProcessManager ---
add_library(Core_ProcessManager STATIC
    ProcessManager/ProcessManager.cpp
)
target_include_directories(Core_ProcessManager PUBLIC
    ${CORE_INCLUDE_DIR}
)
target_link_libraries(Core_ProcessManager PUBLIC Qt6::Core)


# --- Библиотека Utils (содержит только заголовки) ---
add_library(Core_Utils INTERFACE)
target_include_directories(Core_Utils INTERFACE
    ${CORE_INCLUDE_DIR}
)

# --- Библиотека Navigation ---
add_library(Core_Navigation STATIC
    Navigation/NavMeshManager.cpp
    Navigation/PathfindingService.cpp
)
target_include_directories(Core_Navigation PUBLIC
    ${CORE_INCLUDE_DIR}
)
target_link_libraries(Core_Navigation PUBLIC
    Qt6::Core
    RecastNavigation::Recast
    RecastNavigation::Detour
    RecastNavigation::DetourTileCache
    Core_Utils
)

# --- Библиотека HookManager ---
add_library(Core_HookManager STATIC
    HookManager/HookManager.cpp
    HookManager/Hook/InlineHook/InlineHook.cpp
)
target_include_directories(Core_HookManager PUBLIC
    ${CORE_INCLUDE_DIR}
    $<TARGET_PROPERTY:capstone::capstone,INTERFACE_INCLUDE_DIRECTORIES>
)
target_link_libraries(Core_HookManager PUBLIC
    capstone::capstone
    Core_MemoryManager
    Core_Utils # Хукам тоже могут понадобиться утилиты
    Qt6::Core
)


# --- Библиотека Character ---
add_library(Core_Character STATIC
    Bot/Character/Character.cpp
    Bot/Character/CharacterHook.cpp
)
target_include_directories(Core_Character PUBLIC
    ${CORE_INCLUDE_DIR}
)
target_link_libraries(Core_Character PUBLIC
    Core_HookManager
    Core_MemoryManager
    Core_Utils
    Qt6::Core
)

# --- Библиотека Teleport ---
add_library(Core_Teleport STATIC
    Bot/Movement/Teleport/TeleportStepFlagHook.cpp
    Bot/Movement/Teleport/TeleportExecutor.cpp
)
target_include_directories(Core_Teleport PUBLIC
    ${CORE_INCLUDE_DIR}
)
target_link_libraries(Core_Teleport PUBLIC
    Core_HookManager
    Qt6::Core
)