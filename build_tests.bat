@echo off
REM Сборка только тестов (предполагается, что cmake уже был вызван)
cmake --build build --target test_InlineHook
pause