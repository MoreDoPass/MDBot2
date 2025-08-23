cmake_minimum_required(VERSION 3.22)
project(MDHack LANGUAGES CXX)

# --- Устанавливаем переменные для удобства ---
set(GUI_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/gui)
set(CORE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/core)

# --- Создаем исполняемый файл MDHack ---
add_executable(MDHack
    # Основной файл
    src/main.cpp

    # Файлы GUI
    ${GUI_SRC_DIR}/mainwindow.cpp
    ${GUI_SRC_DIR}/processlistdialog.cpp

    # Файлы "ядра" MDHack (пока они существуют)
    ${CORE_SRC_DIR}/appcontext.cpp
    ${CORE_SRC_DIR}/locations/locationmanager.cpp # Предполагая, что locationManager здесь
    ${CORE_SRC_DIR}/player/player.cpp             # Предполагая, что player здесь
)

# --- Указываем, где искать заголовочные файлы ---
# Добавляем корень MDHack/src и корень MDBot2/src
target_include_directories(MDHack PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src 
)

# --- Линкуем MDHack со всеми нужными библиотеками ---
# Здесь происходит магия: мы линкуемся с core-библиотеками из MDBot2!
target_link_libraries(MDHack PRIVATE 
    # Внешние библиотеки
    Qt6::Widgets 
    capstone::capstone
    
    # Наши внутренние core-библиотеки из MDBot2
    Core_MemoryManager
    Core_ProcessManager
    Core_HookManager
    Core_Character
    Core_Teleport
)

# --- Копирование плагина платформы Qt (qwindowsd.dll) для Debug-сборки ---
# Эта команда будет выполнена ПОСЛЕ сборки MDHack.exe
add_custom_command(TARGET MDHack POST_BUILD
    # 1. Создать папку "platforms" рядом с MDHack.exe
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:MDHack>/platforms"
    # 2. Скопировать туда qwindowsd.dll, если она отличается
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        # ПУТЬ-ИСТОЧНИК: Где лежит DLL в твоей установке vcpkg
        "C:/Dev/vcpkg/installed/x86-windows/debug/Qt6/plugins/platforms/qwindowsd.dll"
        # ПУТЬ-НАЗНАЧЕНИЕ: Папка platforms рядом с exe-файлом
        "$<TARGET_FILE_DIR:MDHack>/platforms/"
)