#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <QThread>
#include <QString>
#include <memory>  // Для std::unique_ptr
#include "core/MemoryManager/MemoryManager.h"
#include "core/HookManager/HookManager.h"
#include "core/Bot/Character/Character.h"
#include "core/Bot/Movement/MovementManager.h"
#include "core/Bot/GameObjectManager/GameObjectManager.h"
#include "core/SharedMemoryManager/SharedMemoryManager.h"
#include "Shared/Data/SharedData.h"

// Прямое объявление, чтобы не включать полный заголовок
class GetComputerNameHook;

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
     * @param computerNameToSet Имя компьютера, которое будет установлено через хук. Если пустое, хук не ставится.
     * @param parent Родительский QObject.
     */
    explicit Bot(qint64 processId, const QString& processName, const QString& computerNameToSet,
                 QObject* parent = nullptr);
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
    GameObjectManager* gameObjectManager() const;

   public slots:
    /**
     * @brief Основной цикл работы бота (вызывается из отдельного потока).
     *        Здесь реализуется вся логика автоматизации.
     */
    void run();
    void stop();

    /**
     * @brief Слот для обработки запроса на отладочные данные от GUI.
     * @details Читает последние данные из Shared Memory и отправляет их
     *          обратно в GUI через сигнал debugDataReady.
     */
    void provideDebugData();

   signals:
    /**
     * @brief Сигнал завершения работы бота (например, по ошибке или по команде).
     */
    void finished();

    /**
     * @brief Сигнал, отправляющий свежие данные в GUI для отображения.
     * @param data Структура с данными об игроке и видимых объектах.
     */
    void debugDataReady(const SharedData& data);

   private:
    qint64 m_processId;             ///< PID процесса WoW
    QString m_processName;          ///< Имя процесса (run.exe, Wow.exe)
    MemoryManager m_memoryManager;  ///< Объект MemoryManager для работы с памятью
    HookManager m_hookManager;
    Character* m_character = nullptr;
    MovementManager* m_movementManager = nullptr;
    GameObjectManager* m_gameObjectManager = nullptr;
    bool m_running = false;
    QThread* m_thread = nullptr;

    /// @brief Умный указатель на хук для подмены имени компьютера.
    std::unique_ptr<GetComputerNameHook> m_computerNameHook;

    SharedMemoryManager m_sharedMemory;  ///< Менеджер для работы с общей памятью
    std::wstring m_sharedMemoryName;     ///< Уникальное имя блока общей памяти
};
Q_DECLARE_LOGGING_CATEGORY(logBot)