#pragma once // Защита от двойного включения файла. Обязательна для .h файлов.

#include <QLoggingCategory> // Подключаем необходимый класс из Qt

/**
 * @file Logger.h
 * @brief Объявление глобальных категорий логирования для всего приложения.
 * @details
 *      Подключите этот файл, чтобы использовать макросы логирования Qt (qInfo,
 * qWarning, qCritical). Используйте эти макросы для вывода логов в разных
 * частях программы. Пример: qInfo(lcApp) << "Application has started
 * successfully."; qWarning(lcCore) << "Voxelizer failed to load the mesh,
 * proceeding anyway."; qCritical(lcNav) << "Could not read player coordinates
 * from memory!";
 *
 *      Категории помогают фильтровать вывод логов и понимать, из какой части
 * программы пришло сообщение.
 */

// ОБЪЯВЛЯЕМ (но не определяем) категории.
// Это как сказать "где-то в программе будут такие переменные, компилятор, имей
// в виду". Q_DECLARE_LOGGING_CATEGORY - это специальный макрос Qt.

/// @brief Категория для общих логов приложения (запуск, GUI события, нажатия
/// кнопок).
Q_DECLARE_LOGGING_CATEGORY(lcApp)

/// @brief Категория для логов, связанных с ядром (вокселизация, поиск пути,
/// математика).
Q_DECLARE_LOGGING_CATEGORY(lcCore)

/// @brief Категория для логов, связанных с интеграцией (чтение/запись памяти,
/// управление персонажем).
Q_DECLARE_LOGGING_CATEGORY(lcNav)

void setupLogger();