// --- Файл: src/main.cpp (ИСПРАВЛЕННАЯ ВЕРСИЯ) ---

#include "NavServiceApp.h"
#include <memory>  // <<< НОВОЕ: Нужно для std::unique_ptr

/**
 * @brief Главная точка входа в приложение.
 */
int main(int argc, char* argv[])
{
    // Создаем экземпляр NavServiceApp в динамической памяти (куче),
    // а не на стеке. Это предотвращает переполнение стека.
    // std::unique_ptr автоматически позаботится об удалении объекта
    // при выходе из функции.
    auto app = std::make_unique<NavServiceApp>(argc, argv);

    // Вызываем метод run() через указатель (->)
    return app->run();
}