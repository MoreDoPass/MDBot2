#pragma once
#include <QObject>
#include <QTimer>
#include <QLoggingCategory>
#include <memory>
#include <vector>
#include "shared/Utils/Vector.h"
#include "core/SharedMemoryManager/SharedMemoryManager.h"
#include "Shared/Data/SharedData.h"
#include "core/Bot/Settings/BotSettings.h"

// Прямые объявления, чтобы не подключать тяжелые заголовки в .h
class Character;
class MemoryManager;
class TeleportExecutor;
class TeleportStepFlagHook;

Q_DECLARE_LOGGING_CATEGORY(logMovementManager)

/**
 * @brief Класс, управляющий всеми аспектами движения бота
 */
class MovementManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор.
     * @param sharedMemory Указатель на менеджер общей памяти для отправки команд в DLL.
     * @param memoryManager Указатель на менеджер памяти для работы с хуками и телепортом.
     * @param character Указатель на объект персонажа.
     * @param parent Родительский QObject.
     */
    explicit MovementManager(SharedMemoryManager* sharedMemory, MemoryManager* memoryManager, Character* character,
                             QObject* parent = nullptr);
    ~MovementManager();

    /**
     * @brief Переместиться к точке, используя Click-To-Move через DLL.
     * @param position Координаты цели.
     * @return true, если команда успешно отправлена.
     */
    bool moveTo(const Vector3& position);

    /**
     * @brief Телепортироваться к точке, используя систему пошаговой телепортации.
     * @param position Координаты цели.
     * @return true, если телепортация прошла успешно.
     */
    bool teleportTo(const Vector3& position);

    /**
     * @brief Повернуться лицом к цели, используя Click-To-Move через DLL.
     * @param targetGuid GUID цели, к которой нужно повернуться.
     * @return true, если команда успешно отправлена.
     */
    bool faceTarget(uint64_t targetGuid);

    /**
     * @brief Остановить движение
     */
    void stop();

    void setSettings(const MovementSettings& settings);
    MovementSettings settings() const;

    SharedMemoryManager* getSharedMemory() const
    {
        return m_sharedMemory;
    }

   private slots:
    void updatePathExecution();

   private:
    void onPathFound(std::vector<Vector3> path);

    /**
     * @brief Инициализирует подсистему телепортации (выделяет память, ставит хук).
     * @return true в случае успеха.
     */
    bool initializeTeleportSystem();

    /**
     * @brief Корректно завершает работу подсистемы телепортации (снимает хук, освобождает память).
     */
    void shutdownTeleportSystem();

    // --- СЕРВИСНЫЕ ПОЛЯ ---
    SharedMemoryManager* m_sharedMemory;  ///< Указатель на менеджер общей памяти (для CtM).
    MemoryManager* m_memoryManager;       ///< Указатель на менеджер памяти (для телепорта).
    Character* m_character;               ///< Указатель на объект персонажа.

    // --- ПОЛЯ ДЛЯ СЛЕДОВАНИЯ ПО ПУТИ ---
    MovementSettings m_settings;
    QTimer m_pathExecutorTimer;
    std::vector<Vector3> m_currentPath;
    int m_currentPathIndex = -1;

    // --- ПОЛЯ ДЛЯ СИСТЕМЫ ТЕЛЕПОРТАЦИИ ---
    std::unique_ptr<TeleportExecutor> m_teleportExecutor;  ///< Объект, выполняющий телепортацию.
    std::unique_ptr<TeleportStepFlagHook> m_teleportHook;  ///< Хук, необходимый для телепортации.
    uintptr_t m_playerStructAddrBuffer = 0;                ///< Адрес буфера с указателем на игрока в игре.
    uintptr_t m_flagBuffer = 0;                            ///< Адрес флага-семафора в игре.
    bool m_teleportSystemInitialized = false;              ///< Флаг успешной инициализации системы телепорта.
};