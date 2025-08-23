План Миграции и Разделения MDHack на Core и GUI
Этап 1: "Централизация Ядра" — Создание общей библиотеки Core_Teleport
(Цель: собрать всю низкоуровневую логику телепортации из MDHack в единую, переиспользуемую библиотеку внутри MDBot2.)
Создать новую статическую библиотеку Core_Teleport в CMake.
В MDBot2/src/core/CMakeLists.txt добавить новую цель add_library(Core_Teleport STATIC ...) по аналогии с Core_MemoryManager.
Убедиться, что эта библиотека будет линковаться с Core_MemoryManager, Core_HookManager, и Qt6::Core.
Перенести и адаптировать классы из MDHack в новую библиотеку.
Перенести TeleportStepFlagHook.h/.cpp из mdhack/src/core/teleport в mdbot2/src/core/Bot/Movement/Teleport/.
Рефакторинг TeleportStepFlagHook:
Он больше не наследуется от MDHack::InlineHook. Теперь он должен наследоваться от MDBot2::InlineHook.
Удалить метод createTrampoline(), вместо него реализовать virtual bool generateTrampoline() override;, как того требует MDBot2::InlineHook. Логика останется та же, но в другом методе.
Адаптировать его для работы с MDBot2::MemoryManager.
Перенести teleport.h/.cpp из mdhack/src/core/teleport в ту же папку mdbot2/src/core/Bot/Movement/Teleport/.
Рефакторинг Teleport -> TeleportExecutor:
Переименовать класс в TeleportExecutor, чтобы не путать его с будущим GUI-виджетом.
Заменить зависимость от MDHack::Player и MDHack::AppContext на MDBot2::Character и MDBot2::MemoryManager. Метод setPositionStepwise должен будет принимать их.
Полностью удалить дубликаты из MDHack.
Удалить из MDHack классы MemoryManager, HookManager, IHook, InlineHook, RegisterInlineHook. Все они теперь будут браться из MDBot2/src/core/.
Удалить Player, так как в MDBot2 есть более полный класс Character.
Удалить ProcessManager (есть в MDBot2).
Проверка сборки MDBot2.
Убедиться, что MDBot2 по-прежнему собирается, теперь уже с новой, но пока не используемой библиотекой Core_Teleport.
Этап 2: "Разделение Сборки" — Создание MDHack.exe как отдельного executable
(Цель: Научить CMake собирать MDHack.exe как отдельное приложение, которое использует созданные на 1-м этапе core-библиотеки.)
Создать новый add_executable для MDHack.
В основном CMakeLists.txt проекта MDBot2 добавить add_subdirectory(tools/MDHack).
Создать MDBot2/tools/MDHack/CMakeLists.txt.
В нем определить add_executable(MDHack src/main.cpp src/gui/mainwindow.cpp ...) и перечислить все его .cpp файлы.
Настроить линковку MDHack с core-библиотеками.
В MDBot2/tools/MDHack/CMakeLists.txt добавить target_link_libraries(MDHack PRIVATE ...).
В список библиотек включить Core_MemoryManager, Core_HookManager, Core_Teleport, а также Qt6::Widgets, capstone::capstone.
Адаптировать код MDHack для работы с новыми библиотеками.
Изменить AppContext в MDHack так, чтобы он не создавал свои MemoryManager и HookManager, а использовал классы из Core_ библиотек. AppContext останется как удобная обертка для MDHack.exe.
В mainwindow.cpp MDHack изменить вызов телепортации так, чтобы он использовал новый TeleportExecutor из Core_Teleport.
Проверить сборку всего проекта.
После этого шага в build директории должны появиться два файла: MDBot2.exe и MDHack.exe.
Этап 3: "Интеграция API в Бота" — Подключение телепорта к MovementManager
(Цель: Научить бота использовать Core_Teleport для своих нужд.)
Добавить TeleportExecutor в класс Bot.
В MDBot2/src/core/Bot/Bot.h добавить #include "core/Bot/Movement/Teleport/TeleportExecutor.h".
Добавить член класса std::unique_ptr<TeleportExecutor> m_teleportExecutor.
Инициализировать его в конструкторе Bot::Bot().
Пролинковать MDBot2 с Core_Teleport.
В основном CMakeLists.txt добавить Core_Teleport в target_link_libraries(MDBot2 PRIVATE ...).
Создать API для MovementManager.
В MovementManager добавить логику, которая при определенных условиях (например, включенном чекбоксе и большой дистанции) будет вызывать m_bot->teleportExecutor()->setPositionStepwise(...) вместо поиска пути.
Добавить сам чекбокс "Использовать телепорт" в MainWidget или CharacterWidget, чтобы можно было это включать.
