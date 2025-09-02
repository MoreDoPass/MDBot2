#pragma once
#include <QObject>
#include <QTimer>
#include <QLoggingCategory>
#include <memory>
#include <vector>
#include "shared/Utils/Vector.h"
#include "core/SharedMemoryManager/SharedMemoryManager.h"  // <-- ЗАМЕНА: Подключаем SharedMemoryManager
#include "Shared/Data/SharedData.h"                        // <-- ДОБАВЛЕНИЕ: Нужен для ClientCommandType

class Character;

Q_DECLARE_LOGGING_CATEGORY(logMovementManager)

/**
 * @brief Настройки движения бота
 */
struct MovementSettings
{
    bool useMount = false;
    bool allowFly = false;
    bool allowTeleport = false;
    float ctmDistance = 2.0f;
    enum class NavigationType
    {
        Waypoints,
        MMap,
        Direct
    } navigationType = NavigationType::Waypoints;
};

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
     * @param character Указатель на объект персонажа.
     * @param parent Родительский QObject.
     */
    explicit MovementManager(SharedMemoryManager* sharedMemory, Character* character, QObject* parent = nullptr);
    ~MovementManager();

    /**
     * @brief Переместиться к точке, используя новую систему команд через DLL.
     * @param position Координаты цели.
     * @return true, если команда успешно отправлена.
     */
    bool moveTo(const Vector3& position);

    /**
     * @brief Остановить движение
     */
    void stop();

    void setSettings(const MovementSettings& settings);
    MovementSettings settings() const;

   private slots:
    void updatePathExecution();

   private:
    void onPathFound(std::vector<Vector3> path);

    // --- ИЗМЕНЕННЫЕ ПОЛЯ ---
    SharedMemoryManager* m_sharedMemory;  ///< Указатель на менеджер общей памяти.
    // std::unique_ptr<class CtmExecutor> m_ctm; // <-- УДАЛЕНО

    MovementSettings m_settings;
    QTimer m_pathExecutorTimer;

    std::vector<Vector3> m_currentPath;
    int m_currentPathIndex = -1;
    Character* m_character;
};