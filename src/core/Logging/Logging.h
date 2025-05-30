#pragma once
#include <QLoggingCategory>

// Категории логирования для разных подсистем
Q_DECLARE_LOGGING_CATEGORY(processLog)
Q_DECLARE_LOGGING_CATEGORY(memoryLog)
Q_DECLARE_LOGGING_CATEGORY(hooksLog)
Q_DECLARE_LOGGING_CATEGORY(grindLog)
Q_DECLARE_LOGGING_CATEGORY(combatLog)

// Инициализация системы логирования
void initLogging(bool enableLogging = true, const QString& logFile = QStringLiteral("MDBot2.log"));
void setLogCallback(std::function<void(const QString&)> callback);