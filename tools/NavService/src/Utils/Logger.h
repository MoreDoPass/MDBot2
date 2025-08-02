#pragma once

#include <QLoggingCategory>
#include <QString>
#include <QFile>
#include <QTextStream>
#include <memory>

// Объявляем категории
Q_DECLARE_LOGGING_CATEGORY(navService)
Q_DECLARE_LOGGING_CATEGORY(navMeshLog)
Q_DECLARE_LOGGING_CATEGORY(pathfinder)
Q_DECLARE_LOGGING_CATEGORY(namedPipe)

class Logger
{
   public:
    static bool initialize(const QString& logFilePath = QString());
    static void shutdown();
    static void setLogLevel(const QLoggingCategory& category, QtMsgType level);
    static void setFileLogging(bool enabled);
    static void setConsoleLogging(bool enabled);

   private:
    Logger() = delete;
    ~Logger() = delete;

    // === ИСПРАВЛЕНИЕ ЗДЕСЬ ===
    // Правильный тип для контекста - QMessageLogContext
    static void messageHandler(QtMsgType type, const QMessageLogContext& context, const QString& msg);
    static QString formatMessage(QtMsgType type, const QMessageLogContext& context, const QString& msg);
    static QString getLogLevelString(QtMsgType type);

    // Статические поля
    static std::unique_ptr<QFile> s_logFile;
    static QTextStream s_logStream;
    static bool s_fileLoggingEnabled;
    static bool s_consoleLoggingEnabled;
    static bool s_initialized;
};