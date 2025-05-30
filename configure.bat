@echo off
REM Скрипт для конфигурации проекта MDBot2 с использованием vcpkg toolchain

REM Удаляем старую папку сборки (если есть)
if exist build rmdir /s /q build

REM Запускаем CMake с нужными параметрами
"C:\Program Files\CMake\bin\cmake.exe" -S . -B build -G "Visual Studio 17 2022" -A win32 -DCMAKE_TOOLCHAIN_FILE=C:/Dev/vcpkg/scripts/buildsystems/vcpkg.cmake

pause
