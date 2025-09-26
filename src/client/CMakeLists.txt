project(MDBot_Client)

add_library(MDBot_Client SHARED
    DllMain.cpp
    MainLoop/MainLoopHook.cpp
    Core/Hooking/InlineHook.cpp
    Core/Memory/SharedMemoryConnector.cpp
    Managers/GameObjectManager.cpp
    Managers/CharacterManager/CharacterManager.cpp
    Hooks/VisibleObjectsHook.cpp
    Hooks/CtMEnablerHook.cpp
    Hooks/CharacterHook.cpp
)

find_package(capstone REQUIRED)

# --- КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ ---
target_include_directories(MDBot_Client PRIVATE
    # 1. Путь к самой папке Client (src/Client/)
    ${CMAKE_CURRENT_SOURCE_DIR}
    
    # 2. Путь к папке src/, чтобы можно было писать #include "Shared/..."
    ${CMAKE_CURRENT_SOURCE_DIR}/.. 
)

# Линкуем DLL с нужными библиотеками
if(WIN32)
    target_link_libraries(MDBot_Client PRIVATE
        kernel32
        user32
        capstone::capstone
        Core_Shared # <-- Эта зависимость уже должна быть
        Core_Utils  # <-- Эта зависимость уже должна быть
    )
endif()