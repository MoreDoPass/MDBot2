# Задаем имя для нашей "библиотеки-контракта"
project(MDBot2_Shared)

# Создаем INTERFACE библиотеку. У нее нет исходных файлов для компиляции.
add_library(Core_Shared INTERFACE)

# Указываем, что любой, кто подключит Core_Shared,
# должен получить доступ к заголовочным файлам, лежащим в этой папке.
# ${CMAKE_CURRENT_SOURCE_DIR} - это путь к текущей папке (т.е. src/Shared/)
target_include_directories(Core_Shared INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# --- Библиотека для общих утилит (Vector.h) ---
add_library(Core_Utils INTERFACE)
target_include_directories(Core_Utils INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)