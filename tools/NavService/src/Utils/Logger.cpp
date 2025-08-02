#include "Logger.h"
#include <QCoreApplication>
#include <QDir>
#include <QStandardPaths>
#include <QDateTime>
#include <QFileInfo>
#include <cstdio>  // Используем для fprintf, это более надежно для логов

// Определения статических полей... (остаются как были)
std::unique_ptr<QFile> Logger::s_logFile = nullptr;
QTextStream Logger::s_logStream;
bool Logger::s_fileLoggingEnabled = true;
bool Logger::s_consoleLoggingEnabled = true;
bool Logger::s_initialized = false;

// Определения категорий... (остаются как были)
Q_LOGGING_CATEGORY(navService, "navService")
Q_LOGGING_CATEGORY(navMeshLog, "navMesh")
Q_LOGGING_CATEGORY(pathfinder, "pathfinder")
Q_LOGGING_CATEGORY(namedPipe, "namedPipe")

// ... Код initialize(), shutdown(), setLogLevel(), setFileLogging(), setConsoleLogging()
// ... остается без изменений. Я вставлю его для полноты.

bool Logger::initialize(const QString& logFilePath)
{
    if (s_initialized)
    {
        qCWarning(navService) << "Logger is already initialized";
        return true;
    }
    qInstallMessageHandler(messageHandler);
    if (s_fileLoggingEnabled)
    {
        QString filePath = logFilePath;
        if (filePath.isEmpty())
        {
            QString logDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/logs";
            if (!QDir().mkpath(logDir))
            {
                qCWarning(navService) << "Failed to create log directory:" << logDir;
            }
            filePath = logDir + "/navservice.log";
        }
        s_logFile = std::make_unique<QFile>(filePath);
        if (!s_logFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
        {
            qCWarning(navService) << "Failed to open log file:" << filePath;
            s_fileLoggingEnabled = false;
        }
        else
        {
            s_logStream.setDevice(s_logFile.get());
            qCInfo(navService) << "File logging enabled:" << filePath;
        }
    }
    const_cast<QLoggingCategory&>(navService()).setEnabled(QtDebugMsg, true);
    const_cast<QLoggingCategory&>(navMeshLog()).setEnabled(QtDebugMsg, true);
    const_cast<QLoggingCategory&>(pathfinder()).setEnabled(QtDebugMsg, true);
    const_cast<QLoggingCategory&>(namedPipe()).setEnabled(QtDebugMsg, true);
    s_initialized = true;
    qCInfo(navService) << "Logging system initialized";
    return true;
}

void Logger::shutdown()
{
    if (!s_initialized) return;
    qCInfo(navService) << "Shutting down logging system";
    qInstallMessageHandler(nullptr);
    if (s_logFile && s_logFile->isOpen())
    {
        s_logStream.flush();
        s_logFile->close();
    }
    s_logFile.reset();
    s_initialized = false;
}

void Logger::setLogLevel(const QLoggingCategory& category, QtMsgType level)
{
    const_cast<QLoggingCategory&>(category).setEnabled(QtDebugMsg, level >= QtDebugMsg);
    const_cast<QLoggingCategory&>(category).setEnabled(QtInfoMsg, level >= QtInfoMsg);
    const_cast<QLoggingCategory&>(category).setEnabled(QtWarningMsg, level >= QtWarningMsg);
    const_cast<QLoggingCategory&>(category).setEnabled(QtCriticalMsg, level >= QtCriticalMsg);
    const_cast<QLoggingCategory&>(category).setEnabled(QtFatalMsg, level >= QtFatalMsg);
    qCInfo(navService) << "Log level for category" << category.categoryName() << "set to" << getLogLevelString(level);
}

void Logger::setFileLogging(bool enabled)
{
    s_fileLoggingEnabled = enabled;
}
void Logger::setConsoleLogging(bool enabled)
{
    s_consoleLoggingEnabled = enabled;
}

// === ИСПРАВЛЕНИЕ ЗДЕСЬ ===
// Тип `context` теперь совпадает с объявлением в .h файле
void Logger::messageHandler(QtMsgType type, const QMessageLogContext& context, const QString& msg)
{
    QString formattedMessage = formatMessage(type, context, msg);

    if (s_consoleLoggingEnabled)
    {
        // Используем fprintf для вывода в консоль, это потокобезопаснее
        fprintf(stdout, "%s\n", formattedMessage.toLocal8Bit().constData());
        fflush(stdout);  // Принудительно сбрасываем буфер
    }

    if (s_fileLoggingEnabled && s_logFile && s_logFile->isOpen())
    {
        s_logStream << formattedMessage << Qt::endl;
    }
}

// === ИСПРАВЛЕНИЕ ЗДЕСЬ ===
// Тип `context` теперь совпадает с объявлением в .h файле
QString Logger::formatMessage(QtMsgType type, const QMessageLogContext& context, const QString& msg)
{
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");
    QString level = getLogLevelString(type);
    QString category = context.category ? context.category : "default";

    QString formatted =
        QString("[%1] [%2] [%3] %4").arg(timestamp).arg(level.leftJustified(5, ' ')).arg(category).arg(msg);

    // Добавляем информацию о файле и строке
    if (context.file)
    {
        formatted +=
            QString(" (%1:%2, %3)").arg(QFileInfo(context.file).fileName()).arg(context.line).arg(context.function);
    }
    return formatted;
}

QString Logger::getLogLevelString(QtMsgType type)
{
    switch (type)
    {
        case QtDebugMsg:
            return "DEBUG";
        case QtInfoMsg:
            return "INFO";
        case QtWarningMsg:
            return "WARN";
        case QtCriticalMsg:
            return "ERROR";
        case QtFatalMsg:
            return "FATAL";
        default:
            return "UNKWN";
    }
}