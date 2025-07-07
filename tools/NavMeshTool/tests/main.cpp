#include "gtest/gtest.h"
#include <QCoreApplication>
#include <QLoggingCategory>

// Для getchar() и вывода в консоль
#include <iostream>
#include <cstdio>

// Можно определить глобальную категорию логирования для общих сообщений тестов, если нужно
Q_LOGGING_CATEGORY(logTestRunner, "navmesh.test.runner")

// Включаем наш новый тест через его заголовочный файл
#include "NavMeshGenerator/processAdtTerrain.h"

int main(int argc, char** argv)
{
    // Запускаем тест генерации ландшафта.
    // Если вернет не 0, значит была ошибка, и мы можем остановить выполнение.
    if (runFullTerrainGeneration() != 0)
    {
        return 1;  // Возвращаем код ошибки
    }

    // Инициализация QCoreApplication для Qt логирования во всех тестах.
    // Это важно сделать до InitGoogleTest, если какие-то глобальные
    // объекты или SetUpTestSuite используют Qt.
    // Для QCoreApplication нужен argc > 0 и валидный argv[0]
    // Если тесты запускаются без аргументов, можно передать фиктивные:
    int test_argc = argc > 0 ? argc : 1;
    char* default_argv_str = const_cast<char*>("test_runner_app");
    char** test_argv = argc > 0 ? argv : &default_argv_str;

    QCoreApplication app(test_argc, test_argv);
    // Здесь можно установить глобальные правила фильтрации логов для всех тестов,
    // если они не переопределяются в SetUpTestSuite конкретных тестовых наборов.
    // Например: QLoggingCategory::setFilterRules("*.debug=true\nqt.*.debug=false");

    qCInfo(logTestRunner) << "Initializing Google Test framework...";
    ::testing::InitGoogleTest(&argc, argv);  // Передаем оригинальные argc, argv в GTest

    qCInfo(logTestRunner) << "Running all tests...";
    int result = 1;  // По умолчанию ошибка
    try
    {
        result = RUN_ALL_TESTS();  // Эта функция запускает все тесты, найденные в проекте
    }
    catch (const std::exception& e)
    {
        std::cerr << "[FATAL ERROR] Unhandled std::exception caught in main: " << e.what() << std::endl;
        std::fflush(stderr);  // Сброс буфера для cerr
        qCCritical(logTestRunner) << "[FATAL ERROR] Unhandled std::exception caught in main: " << e.what();
    }
    catch (...)
    {
        std::cerr << "[FATAL ERROR] Unhandled unknown exception caught in main." << std::endl;
        std::fflush(stderr);  // Сброс буфера для cerr
        qCCritical(logTestRunner) << "[FATAL ERROR] Unhandled unknown exception caught in main.";
    }

    qCInfo(logTestRunner) << "All tests finished. Exiting with code:" << result;

    // Добавлено для ожидания ввода перед закрытием консоли
    std::cout << std::endl << "Tests finished. Press Enter to exit..." << std::endl;
    std::fflush(stdout);  // Принудительный сброс буфера для std::cout
    std::getchar();       // Ожидает нажатия Enter

    return result;
}
