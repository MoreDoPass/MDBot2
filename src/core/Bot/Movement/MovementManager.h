#pragma once
#include <QObject>
#include <QLoggingCategory>
#include <memory>
#include "core/Bot/Movement/CtM/CtM.h"
#include "core/Bot/Movement/CtM/CtMEnablerHook.h"

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

   private:
    std::unique_ptr<CtmExecutor> m_ctm;
    std::unique_ptr<CtMEnablerHook> m_ctmEnablerHook;
    MovementSettings m_settings;
};
