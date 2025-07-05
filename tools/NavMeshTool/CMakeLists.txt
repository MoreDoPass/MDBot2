cmake_minimum_required(VERSION 3.16)
project(NavMeshTool LANGUAGES CXX)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/Dev/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # Полезно для Windows, если будете делать библиотеки DLL из частей проекта
set(CMAKE_AUTOMOC ON) # Для Qt Meta-Object Compiler


# Поиск необходимых пакетов
find_package(Qt6 COMPONENTS Core Widgets REQUIRED) # Добавили Widgets
# find_package(StormLib CONFIG REQUIRED) # Не используем, подключаем вручную
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
# Находим пакет Google Test (должен быть найден для сборки тестов)
# Перемещаем это выше, чтобы было доступно для объединенной цели тестов
find_package(GTest CONFIG REQUIRED)

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
    src/core/WoWFiles/Parsers/WDT/WDTParser.cpp
    src/core/WoWFiles/Parsers/ADT/ADTParser.cpp
    src/core/WoWFiles/Parsers/M2/M2Parser.cpp
    src/core/WoWFiles/Parsers/WMO/WMOParser.cpp
    src/core/NavMeshGenerator/NavMeshGenerator.cpp
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

if(WIN32)
    # --- Ручное копирование плагина платформы Qt ---
    # Этот метод менее гибкий, чем windeployqt, но решает конкретную проблему "platform plugin not found".

    # Папка назначения для плагинов (должна называться 'platforms' и находиться рядом с .exe)
    set(PLATFORM_PLUGIN_DEST_DIR "$<TARGET_FILE_DIR:NavMeshTool_app>/platforms")

    # Копируем нужный платформенный плагин в зависимости от конфигурации сборки.
    # Это решает проблему, когда одна из версий (Debug/Release) плагина отсутствует.
    add_custom_command(TARGET NavMeshTool_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${PLATFORM_PLUGIN_DEST_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            # Используем generator expression для выбора нужного файла
            "$<IF:$<CONFIG:Debug>,C:/Dev/vcpkg/installed/x64-windows/debug/Qt6/plugins/platforms/qwindowsd.dll,C:/Dev/vcpkg/installed/x64-windows/Qt6/plugins/platforms/qwindows.dll>"
            ${PLATFORM_PLUGIN_DEST_DIR}
        COMMENT "Copying Qt platform plugin for $<CONFIG> build..."
        VERBATIM
    )
endif()

# Если вы будете использовать StormLib, и он собирается через vcpkg или как часть вашего проекта,
# вам нужно будет настроить его поиск здесь. Примерно так:
# find_package(StormLib CONFIG REQUIRED)
# target_link_libraries(NavMeshTool_app PRIVATE StormLib::StormLib)

# Для начала, этого должно быть достаточно.
# Позже, когда вы добавите больше исходных файлов или зависимостей,
# этот файл нужно будет расширить.

# === Унифицированная цель для всех тестов NavMeshTool ===

# Исходные файлы основных классов, которые будут тестироваться
set(NAVTOOL_CORE_TESTED_SOURCES
    src/core/MpqManager/MpqManager.cpp
    src/core/WoWFiles/Parsers/WDT/WDTParser.cpp
    src/core/WoWFiles/Parsers/ADT/ADTParser.cpp
    src/core/WoWFiles/Parsers/M2/M2Parser.cpp
    src/core/WoWFiles/Parsers/WMO/WMOParser.cpp
    # Добавьте сюда другие .cpp файлы из src/core, которые нужны тестам
)

# Исходные файлы самих тестов
set(NAVTOOL_TEST_SOURCES
    tests/main.cpp
    #tests/MpqManager/TestMpqManager.cpp
    #tests/WDT/TestWdtParser.cpp
    #tests/StormLib/TestStormLibIntegration.cpp
    #tests/ADT/TestADTParser.cpp
    #tests/M2/TestM2Parser.cpp
    tests/WMO/TestWMOParser.cpp
    # Добавляйте сюда другие Test*.cpp файлы
)

if(GTest_FOUND)
    message(STATUS "Google Test FOUND. Configuring NavMeshToolTests target.")
    add_executable(NavMeshToolTests
        ${NAVTOOL_TEST_SOURCES}
        ${NAVTOOL_CORE_TESTED_SOURCES}
    )

    target_include_directories(NavMeshToolTests PRIVATE
        src  # Для доступа к заголовкам типа "core/MpqManager/MpqManager.h"
        tests # Если есть какие-то общие заголовки для тестов в папке tests
        ${STORM_LIB_INCLUDE_DIR} # Заголовки StormLib
        # Qt и GTest заголовки должны быть доступны через find_package
    )

    target_compile_definitions(NavMeshToolTests PRIVATE UNICODE _UNICODE)

    target_link_libraries(NavMeshToolTests PRIVATE
        Qt::Core       # Для QLoggingCategory, QCoreApplication и т.д.
        # Qt::Widgets    # Добавлять, если тесты будут использовать GUI элементы Qt
        GTest::gtest
        GTest::gmock   # Если используете Google Mock
        "${STORM_LIB_LIBRARY_FILE}" # Явно линкуем наш StormLib.lib
        ZLIB::ZLIB
        BZip2::BZip2
    )

    # Копирование тестовых данных WDT для NavMeshToolTests
    set(WDT_TEST_DATA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/WDT/Data")
    set(WDT_TEST_DATA_DEST_DIR "$<TARGET_FILE_DIR:NavMeshToolTests>/Data")

    add_custom_command(TARGET NavMeshToolTests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${WDT_TEST_DATA_DEST_DIR}"
        COMMENT "Creating Data directory for NavMeshToolTests WDT tests"
    )

    file(GLOB_RECURSE WDT_DATA_FILES RELATIVE "${WDT_TEST_DATA_SOURCE_DIR}" CONFIGURE_DEPENDS
        "${WDT_TEST_DATA_SOURCE_DIR}/*"
    )

    foreach(DATA_FILE_RELATIVE ${WDT_DATA_FILES})
        set(DATA_FILE_SOURCE "${WDT_TEST_DATA_SOURCE_DIR}/${DATA_FILE_RELATIVE}")
        set(DATA_FILE_DEST "${WDT_TEST_DATA_DEST_DIR}/${DATA_FILE_RELATIVE}")
        get_filename_component(DATA_FILE_DEST_PARENT_DIR "${DATA_FILE_DEST}" DIRECTORY)
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${DATA_FILE_DEST_PARENT_DIR}"
            COMMENT "Ensuring directory exists for WDT test data ${DATA_FILE_RELATIVE}"
        )
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DATA_FILE_SOURCE}"
                "${DATA_FILE_DEST}"
            COMMENT "Copying WDT test data ${DATA_FILE_RELATIVE} to ${WDT_TEST_DATA_DEST_DIR}"
        )
    endforeach()

    # Копирование тестовых данных MPQ для NavMeshToolTests
    set(MPQ_TEST_DATA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/MpqManager/Data") # Путь к исходным MPQ файлам
    set(MPQ_TEST_DATA_DEST_DIR "$<TARGET_FILE_DIR:NavMeshToolTests>/Data/MpqTestData") # Целевая папка в директории сборки (используем подпапку во избежание конфликтов имен)

    add_custom_command(TARGET NavMeshToolTests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${MPQ_TEST_DATA_DEST_DIR}"
        COMMENT "Creating MpqTestData directory for NavMeshToolTests MPQ tests"
    )

    set(MPQ_TEST_FILES
        "test.mpq"
        "test-2.mpq"
        "test-3.mpq"
    )

    foreach(MPQ_FILE_NAME ${MPQ_TEST_FILES})
        set(MPQ_FILE_SOURCE "${MPQ_TEST_DATA_SOURCE_DIR}/${MPQ_FILE_NAME}")
        set(MPQ_FILE_DEST "${MPQ_TEST_DATA_DEST_DIR}/${MPQ_FILE_NAME}")
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${MPQ_FILE_SOURCE}"
                "${MPQ_FILE_DEST}"
            COMMENT "Copying MPQ test data ${MPQ_FILE_NAME} to ${MPQ_TEST_DATA_DEST_DIR}"
        )
    endforeach()

    # Копирование тестовых данных ADT для NavMeshToolTests
    set(ADT_TEST_DATA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/ADT/Data")
    set(ADT_TEST_DATA_DEST_DIR "$<TARGET_FILE_DIR:NavMeshToolTests>/Data/ADTTestData") # Используем подпапку

    add_custom_command(TARGET NavMeshToolTests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${ADT_TEST_DATA_DEST_DIR}"
        COMMENT "Creating ADTTestData directory for NavMeshToolTests ADT tests"
    )

    # Получаем все .adt файлы из исходной директории данных ADT
    file(GLOB_RECURSE ADT_DATA_FILES RELATIVE "${ADT_TEST_DATA_SOURCE_DIR}" CONFIGURE_DEPENDS
        "${ADT_TEST_DATA_SOURCE_DIR}/*.adt"
    )

    foreach(ADT_DATA_FILE_RELATIVE ${ADT_DATA_FILES})
        set(ADT_DATA_FILE_SOURCE "${ADT_TEST_DATA_SOURCE_DIR}/${ADT_DATA_FILE_RELATIVE}")
        set(ADT_DATA_FILE_DEST "${ADT_TEST_DATA_DEST_DIR}/${ADT_DATA_FILE_RELATIVE}")
        get_filename_component(ADT_DATA_FILE_DEST_PARENT_DIR "${ADT_DATA_FILE_DEST}" DIRECTORY)
        
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${ADT_DATA_FILE_DEST_PARENT_DIR}"
            COMMENT "Ensuring directory exists for ADT test data ${ADT_DATA_FILE_RELATIVE}"
        )
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${ADT_DATA_FILE_SOURCE}"
                "${ADT_DATA_FILE_DEST}"
            COMMENT "Copying ADT test data ${ADT_DATA_FILE_RELATIVE} to ${ADT_TEST_DATA_DEST_DIR}"
        )
    endforeach()

    # Копирование тестовых данных M2 для NavMeshToolTests
    set(M2_TEST_DATA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/M2/Data")
    set(M2_TEST_DATA_DEST_DIR "$<TARGET_FILE_DIR:NavMeshToolTests>/Data/M2TestData") # Используем подпапку

    add_custom_command(TARGET NavMeshToolTests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${M2_TEST_DATA_DEST_DIR}"
        COMMENT "Creating M2TestData directory for NavMeshToolTests M2 tests"
    )

    # Получаем все .m2, .M2 файлы из исходной директории данных M2
    file(GLOB_RECURSE M2_DATA_FILES RELATIVE "${M2_TEST_DATA_SOURCE_DIR}" CONFIGURE_DEPENDS
        "${M2_TEST_DATA_SOURCE_DIR}/*.m2"
        "${M2_TEST_DATA_SOURCE_DIR}/*.M2"
    )

    foreach(M2_DATA_FILE_RELATIVE ${M2_DATA_FILES})
        set(M2_DATA_FILE_SOURCE "${M2_TEST_DATA_SOURCE_DIR}/${M2_DATA_FILE_RELATIVE}")
        set(M2_DATA_FILE_DEST "${M2_TEST_DATA_DEST_DIR}/${M2_DATA_FILE_RELATIVE}")
        get_filename_component(M2_DATA_FILE_DEST_PARENT_DIR "${M2_DATA_FILE_DEST}" DIRECTORY)
        
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${M2_DATA_FILE_DEST_PARENT_DIR}"
            COMMENT "Ensuring directory exists for M2 test data ${M2_DATA_FILE_RELATIVE}"
        )
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${M2_DATA_FILE_SOURCE}"
                "${M2_DATA_FILE_DEST}"
            COMMENT "Copying M2 test data ${M2_DATA_FILE_RELATIVE} to ${M2_TEST_DATA_DEST_DIR}"
        )
    endforeach()

    # Копирование тестовых данных WMO для NavMeshToolTests
    set(WMO_TEST_DATA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/WMO/Data")
    set(WMO_TEST_DATA_DEST_DIR "$<TARGET_FILE_DIR:NavMeshToolTests>/Data") # Копируем в общую папку Data

    add_custom_command(TARGET NavMeshToolTests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${WMO_TEST_DATA_DEST_DIR}"
        COMMENT "Creating Data directory for NavMeshToolTests WMO tests"
    )

    file(GLOB_RECURSE WMO_DATA_FILES RELATIVE "${WMO_TEST_DATA_SOURCE_DIR}" CONFIGURE_DEPENDS
        "${WMO_TEST_DATA_SOURCE_DIR}/*"
    )

    foreach(DATA_FILE_RELATIVE ${WMO_DATA_FILES})
        set(DATA_FILE_SOURCE "${WMO_TEST_DATA_SOURCE_DIR}/${DATA_FILE_RELATIVE}")
        set(DATA_FILE_DEST "${WMO_TEST_DATA_DEST_DIR}/${DATA_FILE_RELATIVE}")
        get_filename_component(DATA_FILE_DEST_PARENT_DIR "${DATA_FILE_DEST}" DIRECTORY)
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${DATA_FILE_DEST_PARENT_DIR}"
            COMMENT "Ensuring directory exists for WMO test data ${DATA_FILE_RELATIVE}"
        )
        add_custom_command(TARGET NavMeshToolTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DATA_FILE_SOURCE}"
                "${DATA_FILE_DEST}"
            COMMENT "Copying WMO test data ${DATA_FILE_RELATIVE} to ${WMO_TEST_DATA_DEST_DIR}"
        )
    endforeach()

    # Включение тестов в CTest
    enable_testing() # Включаем тестирование для проекта (если еще не включено где-то выше)
    add_test(NAME NavMeshToolTests COMMAND NavMeshToolTests)
    message(STATUS "NavMeshToolTests executable configured and added to CTest.")

else()
    message(WARNING "Google Test NOT FOUND. NavMeshToolTests target will not be created.")
endif()

# --- Закомментируем старые отдельные тестовые цели ---
#[[ --- Тест для StormLib в рамках NavMeshTool ---
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
]]

#[[ --- Тест для StormLib с Unicode и Qt логированием в рамках NavMeshTool ---
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
]]

#[[ --- Тест для WDT Parser ---
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/WDT/TestWdtParser.cpp")
    # Находим пакет Google Test
    # find_package(GTest CONFIG REQUIRED) # Уже вызван выше

    set(WDT_PARSER_TEST_SOURCES
        tests/WDT/TestWdtParser.cpp
        src/core/WoWFiles/Parsers/WDT/WDTParser.cpp
    )
    add_executable(NavMesh_WdtParserTest ${WDT_PARSER_TEST_SOURCES})

    target_include_directories(NavMesh_WdtParserTest PRIVATE
        src # Позволит #include "core/WoWFiles/Parsers/WDT/WDTParser.h"
        ${Qt6_Core_INCLUDE_DIRS} # Для QLoggingCategory и других зависимостей Qt из WDTParser
        # GTest::include_dirs # CMake сам должен найти заголовки GTest после find_package
    )

    # Устанавливаем определения для Unicode для теста (если нужно, Qt обычно требует)
    target_compile_definitions(NavMesh_WdtParserTest PRIVATE UNICODE _UNICODE)

    target_link_libraries(NavMesh_WdtParserTest PRIVATE
        Qt::Core # Для QLoggingCategory и других зависимостей Qt
        GTest::gtest
    )
    message(STATUS "NavMesh_WdtParserTest executable will be built and linked with Google Test.")

    # Копирование тестовых данных WDT
    set(WDT_TEST_DATA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/WDT/Data")
    set(WDT_TEST_DATA_DEST_DIR "$<TARGET_FILE_DIR:NavMesh_WdtParserTest>/Data")

    # Создаем папку Data в директории с .exe, если ее нет
    add_custom_command(TARGET NavMesh_WdtParserTest POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${WDT_TEST_DATA_DEST_DIR}"
        COMMENT "Creating Data directory for NavMesh_WdtParserTest"
    )

    # Рекурсивно получаем все файлы из исходной директории данных
    file(GLOB_RECURSE DATA_FILES RELATIVE "${WDT_TEST_DATA_SOURCE_DIR}" CONFIGURE_DEPENDS
        "${WDT_TEST_DATA_SOURCE_DIR}/*"
    )

    foreach(DATA_FILE_RELATIVE ${DATA_FILES})
        set(DATA_FILE_SOURCE "${WDT_TEST_DATA_SOURCE_DIR}/${DATA_FILE_RELATIVE}")
        set(DATA_FILE_DEST "${WDT_TEST_DATA_DEST_DIR}/${DATA_FILE_RELATIVE}")

        # Создаем поддиректории в месте назначения, если они есть в относителньном пути
        get_filename_component(DATA_FILE_DEST_PARENT_DIR "${DATA_FILE_DEST}" DIRECTORY)
        add_custom_command(TARGET NavMesh_WdtParserTest POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${DATA_FILE_DEST_PARENT_DIR}"
            COMMENT "Ensuring directory exists for ${DATA_FILE_RELATIVE}"
        )

        add_custom_command(TARGET NavMesh_WdtParserTest POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DATA_FILE_SOURCE}"
                "${DATA_FILE_DEST}"
            COMMENT "Copying ${DATA_FILE_RELATIVE} to ${WDT_TEST_DATA_DEST_DIR}"
        )
    endforeach()

    # Опционально: Добавление теста в CTest
    enable_testing() # Если еще не включено
    add_test(NAME WdtParserTest COMMAND NavMesh_WdtParserTest)

else()
    message(WARNING "WDT Parser test file not found at ${CMAKE_CURRENT_SOURCE_DIR}/tests/WDT/TestWdtParser.cpp. Test target will not be created.")
endif()
]]
# --- Конец закомментированных старых тестов ---

# Установка основного приложения
install(TARGETS NavMeshTool_app DESTINATION bin) # Копирует .exe в подпапку bin при установке 