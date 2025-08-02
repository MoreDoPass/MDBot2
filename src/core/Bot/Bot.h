#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <QThread>
#include <QString>  // Для QString
#include "core/MemoryManager/MemoryManager.h"
#include "core/HookManager/HookManager.h"
#include "core/Bot/Character/Character.h"
#include "core/Bot/Movement/MovementManager.h"

/**
 * @brief Класс Bot — основной класс для управления одним персонажем WoW.
 *
 * Инкапсулирует PID процесса, работу с памятью (через MemoryManager), данные персонажа и модули бота.
 *
 * Важно: не использовать std::shared_ptr для управления временем жизни Bot!
 * Для работы с потоками Qt используйте обычный указатель и deleteLater.
 */
class Bot : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор Bot.
     * @param processId PID процесса.
     * @param processName Имя процесса (например, "run.exe").
     * @param parent Родительский QObject.
     */
    explicit Bot(qint64 processId, const QString& processName, QObject* parent = nullptr);
    ~Bot();

    /**
     * @brief Получить PID процесса WoW.
     * @return PID процесса.
     */
    qint64 processId() const;
    /**
     * @brief Получить объект Character для доступа к данным персонажа.
     */
    Character* character() const;
    /**
     * @brief Получить менеджер движения
     */
    MovementManager* movementManager() const;

   public slots:
    /**
     * @brief Основной цикл работы бота (вызывается из отдельного потока).
     *        Здесь реализуется вся логика автоматизации.
     */
    void run();
    void stop();

   signals:
    /**
     * @brief Сигнал завершения работы бота (например, по ошибке или по команде).
     */
    void finished();

   private:
    qint64 m_processId;             ///< PID процесса WoW
    QString m_processName;          ///< Имя процесса (run.exe, Wow.exe)
    MemoryManager m_memoryManager;  ///< Объект MemoryManager для работы с памятью
    HookManager m_hookManager;
    Character* m_character = nullptr;
    MovementManager* m_movementManager = nullptr;
    bool m_running = false;
    QThread* m_thread = nullptr;
};
Q_DECLARE_LOGGING_CATEGORY(logBot)
