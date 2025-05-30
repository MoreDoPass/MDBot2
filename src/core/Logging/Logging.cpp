#include "Logging.h"
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>
#include <QCoreApplication>
#include <functional>

// Определение категорий логирования
Q_LOGGING_CATEGORY(processLog, "process")
Q_LOGGING_CATEGORY(memoryLog, "memory")
Q_LOGGING_CATEGORY(hooksLog, "hooks")
Q_LOGGING_CATEGORY(grindLog, "grind")
Q_LOGGING_CATEGORY(combatLog, "combat")

namespace
{
static bool loggingEnabled = true;
static QString logFilePath;
static QMutex logMutex;
static std::function<void(const QString &)> logCallback = nullptr;

void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    if (!loggingEnabled) return;
    QMutexLocker locker(&logMutex);
    QString level;
    switch (type)
    {
        case QtDebugMsg:
            level = "DEBUG";
            break;
        case QtInfoMsg:
            level = "INFO";
            break;
        case QtWarningMsg:
            level = "WARNING";
            break;
        case QtCriticalMsg:
            level = "CRITICAL";
            break;
        case QtFatalMsg:
            level = "FATAL";
            break;
    }
    QString logMessage = QString("%1 [%2] %3 (%4:%5)")
                             .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"))
                             .arg(level)
                             .arg(msg)
                             .arg(context.file ? context.file : "")
                             .arg(context.line);
    // Вывод в файл
    if (!logFilePath.isEmpty())
    {
        QFile file(logFilePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
        {
            QTextStream ts(&file);
            ts << logMessage << '\n';
        }
    }
    // Вывод в пользовательский callback (например, в окно логов)
    if (logCallback)
    {
        logCallback(logMessage);
    }
}
}  // namespace

void initLogging(bool enableLogging, const QString &logFile)
{
    loggingEnabled = enableLogging;
    logFilePath = logFile;
    // Всегда устанавливаем свой message handler!
    qInstallMessageHandler(messageHandler);
}

/**
 * @brief Установить пользовательский обработчик логов (например, для вывода в окно)
 * @param callback Функция, принимающая строку лога
 */
void setLogCallback(std::function<void(const QString &)> callback)
{
    QMutexLocker locker(&logMutex);
    logCallback = std::move(callback);
}
