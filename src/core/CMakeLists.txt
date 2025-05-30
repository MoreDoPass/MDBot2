cmake_minimum_required(VERSION 3.16) # Укажи здесь свою минимально поддерживаемую версию CMake
project(MDBot2CoreLibs LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)

# Добавляем Capstone через vcpkg
# Это нужно, если Capstone используется напрямую в .h/.cpp файлах библиотек ниже
# и если родительский CMakeLists.txt не делает это глобально для всех подпроектов
# так, чтобы это было видно здесь.
find_package(capstone CONFIG REQUIRED)

# --- Библиотека MemoryManager ---
# Предполагается, что MemoryManager.h и MemoryManager.cpp находятся в MDBot2/src/core/MemoryManager/
add_library(Core_MemoryManager STATIC
    MemoryManager/MemoryManager.cpp
    # MemoryManager/MemoryManager.h # .h файлы обычно не добавляют сюда, если они не требуют спец. обработки (например, moc для Qt)
    # Если есть другие .cpp файлы для MemoryManager, добавь их сюда.
)
# PUBLIC: ${CMAKE_CURRENT_SOURCE_DIR} (т.е. MDBot2/src/core/) будет добавлен в пути поиска
# заголовочных файлов для всех, кто линкуется с Core_MemoryManager.
# Это позволит писать, например, #include "MemoryManager/MemoryManager.h"
target_include_directories(Core_MemoryManager PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# Связываем Core_MemoryManager с Qt6::Core, так как MemoryManager.h (или его зависимости) может включать QObject
# Предполагается, что Qt6::Core УЖЕ найдена в родительском CMakeLists.txt
if(TARGET Qt6::Core)
    target_link_libraries(Core_MemoryManager PUBLIC Qt6::Core)
else()
    message(WARNING "Цель Qt6::Core не найдена. Core_MemoryManager может не скомпилироваться, если использует Qt.")
endif()


# --- Библиотека ProcessManager ---
# Предполагается, что ProcessManager.h и ProcessManager.cpp находятся в MDBot2/src/core/ProcessManager/
add_library(Core_ProcessManager STATIC
    ProcessManager/ProcessManager.cpp
    # ProcessManager/ProcessManager.h
    # Если есть другие .cpp файлы для ProcessManager, добавь их сюда.
)
target_include_directories(Core_ProcessManager PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# Связываем Core_ProcessManager с Qt6::Core, если он использует Qt
if(TARGET Qt6::Core)
    target_link_libraries(Core_ProcessManager PUBLIC Qt6::Core)
else()
    message(WARNING "Цель Qt6::Core не найдена. Core_ProcessManager может не скомпилироваться, если использует Qt.")
endif()

# --- Другие core библиотеки можно добавить здесь по аналогии --- 

# --- Библиотека HookManager ---
# Собираем все .cpp файлы из HookManager и его поддиректорий
add_library(Core_HookManager STATIC
    HookManager/HookManager.cpp
    # HookManager/Hook/Hook.cpp # Если бы он был, добавили бы сюда
    HookManager/Hook/InlineHook/InlineHook.cpp
)

# Добавляем директорию src/core/ в пути поиска заголовочных файлов
# Это позволит писать, например, #include "HookManager/HookManager.h"
# или #include "HookManager/Hook/InlineHook/InlineHook.h"
target_include_directories(Core_HookManager PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    $<TARGET_PROPERTY:capstone::capstone,INTERFACE_INCLUDE_DIRECTORIES> # Добавляем пути Capstone
)

# HookManager, вероятно, зависит от Core_MemoryManager (InlineHook его использует)
# и, возможно, от Qt, если его заголовки используют Qt-типы (например, QLoggingCategory)
# А также от Capstone
target_link_libraries(Core_HookManager PUBLIC
    capstone::capstone # Линкуем с Capstone
)

if(TARGET Core_MemoryManager)
    target_link_libraries(Core_HookManager PUBLIC Core_MemoryManager)
else()
    message(WARNING "Цель Core_MemoryManager не найдена. Core_HookManager может не слинковаться.")
endif()

if(TARGET Qt6::Core) # Если используются QLoggingCategory или другие Qt Core типы
    target_link_libraries(Core_HookManager PUBLIC Qt6::Core)
else()
    message(WARNING "Цель Qt6::Core не найдена. Core_HookManager может не скомпилироваться, если использует Qt.")
endif() 