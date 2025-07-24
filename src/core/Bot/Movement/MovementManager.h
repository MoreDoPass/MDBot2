#pragma once
#include <QObject>
#include <QTimer>  // Добавляем QTimer
#include <QLoggingCategory>
#include <memory>
#include <vector>
#include "core/Bot/Movement/CtM/CtM.h"
#include "core/Bot/Movement/CtM/CtMEnablerHook.h"
#include "core/Navigation/PathfindingService.h"  // Интеграция с сервисом поиска пути
#include "core/Utils/Vector.h"                   // Для использования Vector3

Q_DECLARE_LOGGING_CATEGORY(logMovementManager)

/**
 * @brief Настройки движения бота
 */
struct MovementSettings
{
    bool useMount = false;       ///< Использовать маунт
    bool allowFly = false;       ///< Разрешить полёт
    bool allowTeleport = false;  ///< Разрешить телепорт-хак
    float ctmDistance = 2.0f;    ///< Дистанция для CtM
    enum class NavigationType
    {
        Waypoints,
        MMap,
        Direct
    } navigationType = NavigationType::Waypoints;
};

/**
 * @brief Класс, управляющий всеми аспектами движения бота
 *
 * - Выбор способа перемещения (пешком, маунт, полёт, телепорт)
 * - Навигация (waypoints, mmaps)
 * - Делегирование низкоуровневого CtM
 */
class MovementManager : public QObject
{
    Q_OBJECT
   public:
    explicit MovementManager(class MemoryManager* memory, QObject* parent = nullptr);
    ~MovementManager();

    /**
     * @brief Переместиться к точке
     * @param x X
     * @param y Y
     * @param z Z
     * @param settings Настройки движения
     * @return true если команда отправлена
     */
    bool moveTo(float x, float y, float z, const MovementSettings& settings);

    /**
     * @brief Остановить движение
     */
    void stop();

    /**
     * @brief Изменить настройки движения
     */
    void setSettings(const MovementSettings& settings);

    /**
     * @brief Получить текущие настройки
     */
    MovementSettings settings() const;

   private slots:
    /**
     * @brief Слот, вызываемый по таймеру для обновления логики следования по пути.
     */
    void updatePathExecution();

   private:
    /**
     * @brief Callback-функция, вызываемая PathfindingService по завершении поиска пути.
     * @param path - Найденный путь. Если путь не найден, вектор будет пустым.
     */
    void onPathFound(std::vector<Vector3> path);

    std::unique_ptr<class CtmExecutor> m_ctm;
    std::unique_ptr<class CtMEnablerHook> m_ctmEnablerHook;
    MovementSettings m_settings;
    QTimer m_pathExecutorTimer;  ///< Таймер для проверки продвижения по пути.

    std::vector<Vector3> m_currentPath;  ///< Текущий рассчитанный путь.
    int m_currentPathIndex = -1;         ///< Индекс текущей точки в m_currentPath, к которой движется бот.
};
