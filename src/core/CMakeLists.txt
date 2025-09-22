cmake_minimum_required(VERSION 3.16)
project(MDBot2CoreLibs LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)

# Базовая директория для поиска всех core-заголовков.
# ${CMAKE_CURRENT_SOURCE_DIR} - это .../src/core, нам нужен уровень выше.
set(CORE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

# --- Behavior Tree ---
# Создаем статическую библиотеку для универсальных компонентов дерева
add_library(Core_BehaviorTree STATIC
    BehaviorTree/SequenceNode.cpp
    BehaviorTree/SelectorNode.cpp   # <-- Добавили
    BehaviorTree/InverterNode.cpp   # <-- Добавили
    BehaviorTree/WhileSuccessDecorator.cpp
)
target_include_directories(Core_BehaviorTree PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
# Вот она, недостающая часть!
target_link_libraries(Core_BehaviorTree PUBLIC Qt6::Core)

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

# --- Библиотека InjectionManager ---
add_library(Core_InjectionManager STATIC
    InjectionManager/InjectionManager.cpp
)
target_include_directories(Core_InjectionManager PUBLIC
    # Указываем, что его заголовки лежат в общей директории core
    ${CORE_INCLUDE_DIR}
)
# InjectionManager не зависит от других наших библиотек, но может использовать Qt для логирования в будущем
target_link_libraries(Core_InjectionManager PUBLIC Qt6::Core)

# --- Библиотека SharedMemoryManager ---
add_library(Core_SharedMemoryManager STATIC
    SharedMemoryManager/SharedMemoryManager.cpp
)
target_include_directories(Core_SharedMemoryManager PUBLIC
    ${CORE_INCLUDE_DIR}
)
# Эта библиотека будет использовать наш "контракт" из Core_Shared
target_link_libraries(Core_SharedMemoryManager PUBLIC
    Core_Shared
    Qt6::Core
)

# --- Библиотека HookManager ---
add_library(Core_HookManager STATIC
    HookManager/HookManager.cpp
    HookManager/Hook/InlineHook/InlineHook.cpp
    Bot/Hooks/GetComputerNameHook.cpp
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

add_library(Core_GameObject STATIC
    Bot/GameObjectManager/GameObjectManager.cpp
)
target_include_directories(Core_GameObject PUBLIC
    ${CORE_INCLUDE_DIR}
)
target_link_libraries(Core_GameObject PUBLIC
    Core_MemoryManager
    Core_Utils
    Qt6::Core
)

add_library(Core_Database STATIC
    Database/ResourceDatabase.cpp
)
target_include_directories(Core_Database PUBLIC
    ${CORE_INCLUDE_DIR}
)
# Database не зависит от других наших либ, только от Qt (для QString, QVector и т.д. в будущем)
target_link_libraries(Core_Database PUBLIC
    Qt6::Core
)

# --- НОВЫЙ БЛОК: Библиотека ProfileManager ---
add_library(Core_ProfileManager STATIC
    ProfileManager/ProfileManager.cpp
)
target_include_directories(Core_ProfileManager PUBLIC
    ${CORE_INCLUDE_DIR}
)
# ProfileManager будет использовать Qt для парсинга JSON и логирования.
# Он не зависит от других наших библиотек.
target_link_libraries(Core_ProfileManager PUBLIC
    Qt6::Core
)

# --- НОВЫЙ БЛОК: Библиотека BlacklistManager ---
add_library(Core_BlacklistManager STATIC
    BlacklistManager/BlacklistManager.cpp
)
target_include_directories(Core_BlacklistManager PUBLIC
    ${CORE_INCLUDE_DIR}
)
# BlacklistManager использует Qt для работы с файлами, JSON и логированием.
target_link_libraries(Core_BlacklistManager PUBLIC
    Qt6::Core
)