#include "Logger.h" // Подключаем наш заголовочный файл, чтобы реализовать то, что в нем объявлено

// ОПРЕДЕЛЯЕМ категории, которые были объявлены в .h файле.
// Это как сказать "вот они, эти переменные".
// Имя в кавычках - это то, что будет выводиться в консоли.
Q_LOGGING_CATEGORY(lcApp, "app")
Q_LOGGING_CATEGORY(lcCore, "core")
Q_LOGGING_CATEGORY(lcNav, "nav")

/**
 * @brief Реализация функции настройки логгера.
 */
void setupLogger() {
  // Устанавливаем правила фильтрации по умолчанию.
  // " *.debug=true " означает, что мы хотим видеть все сообщения уровня Debug и
  // выше (Info, Warning, Critical). " qt.qpa.input.events=false " отключает
  // очень назойливые системные логи Qt о каждом движении мыши.
  QString rules =
      // 1. По умолчанию отключаем ВСЕ категории Qt,
      //    которые начинаются с "qt.". Это уберет 99% спама.
      "qt.*.debug=false\n"
      // 2. Включаем все НАШИ категории (app, core, nav).
      "app.debug=true\n"
      "core.debug=true\n"
      "nav.debug=true";

  QLoggingCategory::setFilterRules(rules);

  // Устанавливаем единый формат для всех логов.
  // Это самая важная часть. Здесь мы определяем, как будет выглядеть каждая
  // строка в консоли.
  // [%{time yyyy-MM-dd hh:mm:ss.zzz}] - Время с точностью до миллисекунд
  // [%{type}]                         - Тип сообщения (DEBUG, INFO, WARNING,
  // CRITICAL)
  // [%{category}]                     - Имя нашей категории (app, core, nav)
  // %{message}                         - Само сообщение, которое мы передаем
  // через <<
  // (%{file}:%{line})                  - Имя файла и номер строки, откуда был
  // вызван лог (очень полезно для отладки!)
  qSetMessagePattern("[%{time yyyy-MM-dd hh:mm:ss.zzz}] [%{type}] "
                     "[%{category}] %{message} (%{file}:%{line})");

  // Выводим первое сообщение, чтобы убедиться, что логгер настроен.
  // Это сообщение будет использовать новый формат.
  qInfo(lcApp) << "Logger has been successfully initialized.";
}