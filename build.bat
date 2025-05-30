@echo off
REM Скрипт для сборки проекта MDBot2

REM Переходим в папку build
cd /d %~dp0build

REM Запускаем сборку через MSBuild
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" MDBot2.sln /p:Configuration=Debug /m

pause
