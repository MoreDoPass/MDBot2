TODO-ПЛАН: Интеграция Behavior Tree
Цель: Создать и запустить минимально работающий прототип бота, который использует архитектуру Behavior Tree для выполнения одного простого действия: поиска цели.
ЭТАП 1: Создание Базовой Инфраструктуры (Инструментарий)
Задача: Заложить фундамент - универсальные классы для дерева, которые не зависят от логики игры.
Создать новую директорию для универсальных компонентов дерева: src/core/BehaviorTree/.
Определить "Контекст" (BTContext):
В src/core/BehaviorTree/ создать файл BTContext.h.
Внутри описать класс BTContext, который будет содержать указатели на все необходимые менеджеры (Character, GameObjectManager и т.д.) и поле для хранения временных данных (например, currentTargetGuid).
Определить Базовый Узел (BTNode):
В src/core/BehaviorTree/ создать файл BTNode.h.
Внутри описать перечисление NodeStatus (Success, Failure, Running).
Описать абстрактный класс BTNode с одним виртуальным методом tick(BTContext& context).
Реализовать Композитный Узел "Последовательность" (SequenceNode):
В src/core/BehaviorTree/ создать файлы SequenceNode.h и .cpp.
Реализовать логику последовательного выполнения дочерних узлов: останавливаться, если один из них вернул Failure или Running.
Настроить Систему Сборки:
В src/core/CMakeLists.txt создать новую статическую библиотеку Core_BehaviorTree из созданных файлов.
В корневом CMakeLists.txt прилинковать Core_BehaviorTree к основному исполняемому файлу MDBot2.



ЭТАП 2: Создание Специфичных для Игры Компонентов
Задача: Создать первые "навыки" и "план" для конкретной задачи бота.
Организовать структуру для "Навыков" (Behaviors):
Создать директорию src/core/Bot/Behaviors/.
Внутри создать поддиректорию для первой категории навыков, например, Grind/.
Реализовать первый "Навык" (FindCritterAction):
В src/core/Bot/Behaviors/Grind/ создать файлы FindCritterAction.h и .cpp.
Унаследовать класс от BTNode.
В методе tick реализовать логику поиска объекта типа "Critter" через GameObjectManager (полученный из BTContext).
При успехе записывать GUID найденной цели в BTContext.
Организовать структуру для "Планов" (Logic):
Создать директорию src/core/Bot/Logic/.
Реализовать первый "План" (CritterGrindLogic):
В src/core/Bot/Logic/ создать файлы CritterGrindLogic.h и .cpp.
Создать статический метод build(), который возвращает std::unique_ptr<BTNode>.
Внутри build() создать и вернуть дерево, состоящее из одного узла FindCritterAction.
Настроить Систему Сборки:
В корневом CMakeLists.txt добавить новые .cpp файлы (FindCritterAction.cpp и CritterGrindLogic.cpp) в список исходников для MDBot2.
ЭТАП 3: Интеграция "Мозга" в Класс Bot
Задача: Связать созданную инфраструктуру с основным классом бота.
Модифицировать Bot.h:
Подключить <memory>.
Добавить прямые объявления для BTNode и BTContext.
Добавить в приватные члены класса два поля: std::unique_ptr<BTNode> m_behaviorTreeRoot и std::unique_ptr<BTContext> m_btContext.
Модифицировать конструктор Bot::Bot(...):
После инициализации всех менеджеров (m_character, m_gameObjectManager и т.д.):
Создать экземпляр BTContext.
Заполнить BTContext указателями на менеджеры текущего экземпляра Bot.
Вызвать статический метод CritterGrindLogic::build() и сохранить результат в m_behaviorTreeRoot.
Переработать основной цикл Bot::run():
Удалить всю существующую логику принятия решений.
Оставить только три основных шага:
Обновление данных из общей памяти (m_gameObjectManager->update..., m_character->update...).
Вызов m_behaviorTreeRoot->tick(*m_btContext); (если m_behaviorTreeRoot не null).
Пауза (QThread::msleep).
ЭТАП 4: Тестирование
Скомпилировать проект.
Запустить MDBot2 и подключиться к процессу WoW.
Наблюдать за логами: убедиться, что при нахождении "Critter" в игре в логе появляется соответствующее сообщение от FindCritterAction.