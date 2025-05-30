cmake_minimum_required(VERSION 3.16)
project(NavMeshTool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # Полезно для Windows, если будете делать библиотеки DLL из частей проекта
set(CMAKE_AUTOMOC ON) # Для Qt Meta-Object Compiler

# Поиск необходимых пакетов
find_package(Qt6 COMPONENTS Core Widgets REQUIRED) # Добавили Widgets
# find_package(StormLib CONFIG REQUIRED) # Не используем, подключаем вручную
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)

# --- Настройка для вручную собранной StormLib ---
# Путь к директории с StormLib.h и другими заголовочными файлами StormLib
set(STORM_LIB_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/stormlib/StormLib/src")

# Путь к скомпилированному файлу StormLib.lib (Release, Unicode, x86)
set(STORM_LIB_LIBRARY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/stormlib/StormLib/build/Release/StormLib.lib") # Убедись, что этот путь верен!

# Проверяем, существует ли файл библиотеки StormLib
if(NOT EXISTS "${STORM_LIB_LIBRARY_FILE}")
    message(FATAL_ERROR "Файл библиотеки StormLib не найден по пути: ${STORM_LIB_LIBRARY_FILE}. Пожалуйста, проверьте путь и соберите StormLib.")
else()
    message(STATUS "Файл библиотеки StormLib найден: ${STORM_LIB_LIBRARY_FILE}")
endif()
# --- Конец настройки для StormLib ---

# Список исходных файлов для основного приложения
set(NAV_MESH_TOOL_APP_SOURCES
    src/main.cpp
    src/Core/MpqManager/MpqManager.cpp
    src/gui/MainWindow.h             # <--- Добавили MainWindow.h
    src/gui/MainWindow.cpp           # <--- Добавили MainWindow.cpp
)

# Создаем исполняемый файл приложения
add_executable(NavMeshTool_app ${NAV_MESH_TOOL_APP_SOURCES})

# Указываем пути для поиска заголовочных файлов для приложения
target_include_directories(NavMeshTool_app PRIVATE
    src  # Позволит писать #include "Core/MpqManager/MpqManager.h" и т.п.
    ${Qt6_Core_INCLUDE_DIRS} # Добавляем пути к заголовкам Qt Core
    ${Qt6_Widgets_INCLUDE_DIRS} # <--- Добавили пути для Qt Widgets
    ${STORM_LIB_INCLUDE_DIR} # <--- Путь к заголовкам StormLib
    # Если у вас будут заголовочные файлы в других местах, добавьте их сюда
    # например, ${PROJECT_SOURCE_DIR}/include
)

# Устанавливаем определения для Unicode
target_compile_definitions(NavMeshTool_app PRIVATE UNICODE _UNICODE)

# Подключаем библиотеки к приложению
target_link_libraries(NavMeshTool_app PRIVATE
    Qt::Core # Связываем с Qt Core
    Qt::Widgets # <--- Связываем с Qt Widgets
    "${STORM_LIB_LIBRARY_FILE}" # <--- Явно линкуем наш StormLib.lib
    ZLIB::ZLIB
    BZip2::BZip2
)

# Если вы будете использовать StormLib, и он собирается через vcpkg или как часть вашего проекта,
# вам нужно будет настроить find_package(StormLib REQUIRED) и связать его.
# Пример для vcpkg (если StormLib установлен через vcpkg и интегрирован с CMake проектом):
# find_package(StormLib CONFIG REQUIRED)
# target_link_libraries(NavMeshTool_app PRIVATE StormLib::StormLib)

# Для начала, этого должно быть достаточно.
# Позже, когда вы добавите больше исходных файлов или зависимостей,
# этот файл нужно будет расширить.

# --- Тест для StormLib в рамках NavMeshTool ---
# Проверяем, существует ли тестовый файл
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/stormlib_test.cpp")
    set(STORM_LIB_TEST_SOURCES
        tests/stormlib_test.cpp
    )
    add_executable(NavMesh_StormLibTest ${STORM_LIB_TEST_SOURCES})
    
    target_include_directories(NavMesh_StormLibTest PRIVATE
        src # Если тесту нужны другие заголовки из NavMeshTool
        ${STORM_LIB_INCLUDE_DIR} # <--- Путь к заголовкам StormLib
        # ${Qt6_Core_INCLUDE_DIRS} # Раскомментируй, если тест использует Qt напрямую
    )

    # Устанавливаем определения для Unicode для теста
    target_compile_definitions(NavMesh_StormLibTest PRIVATE UNICODE _UNICODE)

    target_link_libraries(NavMesh_StormLibTest PRIVATE
        # Qt::Core # Раскомментируй, если тест использует Qt напрямую
        # StormLib::storm # <-- Комментируем
        "${STORM_LIB_LIBRARY_FILE}" # <--- Явно линкуем наш StormLib.lib
        ZLIB::ZLIB
        BZip2::BZip2
    )
    message(STATUS "NavMesh_StormLibTest executable will be built using StormLib: ${STORM_LIB_LIBRARY_FILE}")
else()
    message(WARNING "StormLib test file not found at ${CMAKE_CURRENT_SOURCE_DIR}/tests/stormlib_test.cpp. Test target will not be created.")
endif()

# --- Тест для StormLib с Unicode и Qt логированием в рамках NavMeshTool ---
# Проверяем, существует ли тестовый файл
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/stormlib_test_unicode_qt.cpp")
    set(STORM_LIB_UNICODE_QT_TEST_SOURCES
        tests/stormlib_test_unicode_qt.cpp
    )
    add_executable(NavMesh_StormLibTestUnicodeQt ${STORM_LIB_UNICODE_QT_TEST_SOURCES})
    
    target_include_directories(NavMesh_StormLibTestUnicodeQt PRIVATE
        src # Если тесту нужны другие заголовки из NavMeshTool
        ${STORM_LIB_INCLUDE_DIR} # <--- Путь к заголовкам StormLib
        ${Qt6_Core_INCLUDE_DIRS} # <--- Путь к заголовкам Qt Core
    )

    # Устанавливаем определения для Unicode для теста
    target_compile_definitions(NavMesh_StormLibTestUnicodeQt PRIVATE UNICODE _UNICODE)

    target_link_libraries(NavMesh_StormLibTestUnicodeQt PRIVATE
        Qt::Core # <--- Связываем с Qt Core
        "${STORM_LIB_LIBRARY_FILE}" # <--- Явно линкуем наш StormLib.lib
        ZLIB::ZLIB
        BZip2::BZip2
    )
    message(STATUS "NavMesh_StormLibTestUnicodeQt executable will be built using StormLib: ${STORM_LIB_LIBRARY_FILE} and Qt Core.")
else()
    message(WARNING "StormLib Unicode Qt test file not found at ${CMAKE_CURRENT_SOURCE_DIR}/tests/stormlib_test_unicode_qt.cpp. Test target will not be created.")
endif()

# --- Начало секции копирования зависимостей Qt для NavMeshTool_app (vcpkg x86 - ручное копирование) ---

if(WIN32) # Условие теперь только на WIN32
    message(STATUS "NAV ਮESH_TOOL_DEPLOY: WIN32 detected. Setting up Qt deployment commands for NavMeshTool_app.")

    # Пути к твоей установке vcpkg x86-windows. ПОЖАЛУЙСТА, ПРОВЕРЬ И СКОРРЕКТИРУЙ ИХ!
    set(VCPKG_X86_INSTALLED_DIR "C:/Dev/vcpkg/installed/x86-windows") # Базовый путь

    set(VCPKG_X86_BIN_DIR_DEBUG "${VCPKG_X86_INSTALLED_DIR}/debug/bin")
    set(VCPKG_X86_PLUGINS_DIR_DEBUG "${VCPKG_X86_INSTALLED_DIR}/debug/Qt6/plugins")
    
    # Для Release (если понадобится, можно будет добавить аналогичные переменные)
    # set(VCPKG_X86_BIN_DIR_RELEASE "${VCPKG_X86_INSTALLED_DIR}/bin")
    # set(VCPKG_X86_PLUGINS_DIR_RELEASE "${VCPKG_X86_INSTALLED_DIR}/Qt6/plugins")

    # 1. Копирование qwindowsd.dll для Debug для NavMeshTool_app
    set(PLATFORM_PLUGIN_SOURCE_DEBUG "${VCPKG_X86_PLUGINS_DIR_DEBUG}/platforms/qwindowsd.dll")
    set(PLATFORM_PLUGIN_DEST_DIR_BASE_APP "$<TARGET_FILE_DIR:NavMeshTool_app>/platforms") 

    message(STATUS "NAV ਮESH_TOOL_DEPLOY: PLATFORM_PLUGIN_SOURCE_DEBUG (qwindowsd.dll) = ${PLATFORM_PLUGIN_SOURCE_DEBUG}")

    if(EXISTS "${PLATFORM_PLUGIN_SOURCE_DEBUG}")
        message(STATUS "NAV ਮESH_TOOL_DEPLOY: qwindowsd.dll (Debug) FOUND. Adding copy command for NavMeshTool_app (Debug config).")
        add_custom_command(TARGET NavMeshTool_app POST_BUILD
            COMMAND $<$<CONFIG:Debug>:${CMAKE_COMMAND}> -E make_directory "${PLATFORM_PLUGIN_DEST_DIR_BASE_APP}"
            COMMAND $<$<CONFIG:Debug>:${CMAKE_COMMAND}> -E copy_if_different
                "${PLATFORM_PLUGIN_SOURCE_DEBUG}"
                "${PLATFORM_PLUGIN_DEST_DIR_BASE_APP}/" 
            COMMENT "Copying qwindowsd.dll for NavMeshTool_app (Debug config)"
            VERBATIM
        )
    else()
        message(WARNING "NAV ਮESH_TOOL_DEPLOY: qwindowsd.dll (Debug) NOT FOUND at ${PLATFORM_PLUGIN_SOURCE_DEBUG}. Please check VCPKG_X86_PLUGINS_DIR_DEBUG.")
    endif()

    # 2. Копирование основных runtime библиотек Qt для Debug для NavMeshTool_app
    set(QT_DEBUG_RUNTIME_DLLS_APP
        "${VCPKG_X86_BIN_DIR_DEBUG}/Qt6Cored.dll"
        "${VCPKG_X86_BIN_DIR_DEBUG}/Qt6Guid.dll"
        "${VCPKG_X86_BIN_DIR_DEBUG}/Qt6Widgetsd.dll"
        # Добавь другие DLL, если они понадобятся (например, Qt6OpenGLd.dll, если будешь использовать OpenGL)
    )

    message(STATUS "NAV ਮESH_TOOL_DEPLOY: Setting up runtime DLL copy commands for NavMeshTool_app (Debug config).")
    foreach(QT_DLL_PATH_VAR ${QT_DEBUG_RUNTIME_DLLS_APP})
        message(STATUS "NAV ਮESH_TOOL_DEPLOY: Checking DLL for NavMeshTool_app (Debug): ${QT_DLL_PATH_VAR}")
        if(EXISTS "${QT_DLL_PATH_VAR}")
            message(STATUS "NAV ਮESH_TOOL_DEPLOY: DLL (Debug) FOUND: ${QT_DLL_PATH_VAR}. Adding copy command for NavMeshTool_app (Debug config).")
            add_custom_command(TARGET NavMeshTool_app POST_BUILD
                COMMAND $<$<CONFIG:Debug>:${CMAKE_COMMAND}> -E copy_if_different
                    "${QT_DLL_PATH_VAR}"
                    "$<TARGET_FILE_DIR:NavMeshTool_app>/" 
                COMMENT "Copying ${QT_DLL_PATH_VAR} for NavMeshTool_app (Debug config)"
                VERBATIM
            )
        else()
            message(WARNING "NAV ਮESH_TOOL_DEPLOY: Required Qt DLL (Debug) NOT FOUND: ${QT_DLL_PATH_VAR}. Please check VCPKG_X86_BIN_DIR_DEBUG.")
        endif()
    endforeach()
else()
    message(STATUS "NAV ਮESH_TOOL_DEPLOY: Not a WIN32 build, skipping Qt deployment commands for NavMeshTool_app.")
endif()

# --- Конец секции копирования зависимостей Qt для NavMeshTool_app ---

# Установка основного приложения
install(TARGETS NavMeshTool_app DESTINATION bin) # Копирует .exe в подпапку bin при установке 