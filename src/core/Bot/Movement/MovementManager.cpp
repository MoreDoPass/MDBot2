#include "MovementManager.h"
#include "core/Bot/Movement/CtM/CtMEnablerHook.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logMovementManager, "mdbot.movementmanager")

MovementManager::MovementManager(MemoryManager* memory, QObject* parent)
    : QObject(parent), m_ctm(std::make_unique<CtmExecutor>(memory))
{
    qCInfo(logMovementManager) << "MovementManager создан";
    // Инициализация CtMEnablerHook
    m_ctmEnablerHook = std::make_unique<CtMEnablerHook>(memory);
    if (!m_ctmEnablerHook->install())
    {
        qCCritical(logMovementManager) << "CtMEnablerHook не удалось установить!";
    }
    else
    {
        qCInfo(logMovementManager) << "CtMEnablerHook успешно установлен";
    }
}

MovementManager::~MovementManager()
{
    qCInfo(logMovementManager) << "MovementManager уничтожен";
}

bool MovementManager::moveTo(float x, float y, float z, const MovementSettings& settings)
{
    m_settings = settings;
    // TODO: здесь можно добавить выбор способа перемещения (маунт, полёт, телепорт)
    // Сейчас только CtM
    qCInfo(logMovementManager) << "moveTo(" << x << y << z << ") ctmDistance:" << settings.ctmDistance;
    return m_ctm->moveTo(x, y, z, settings.ctmDistance);
}

void MovementManager::stop()
{
    // TODO: реализовать остановку движения (CtM IDLE или другое действие)
    qCInfo(logMovementManager) << "Остановка движения (stop)";
    // Например, можно вызвать CtM с action NONE или IDLE
    m_ctm->moveTo(0, 0, 0, 0.1f);  // Пример: CtM в текущую позицию с минимальной дистанцией
}

void MovementManager::setSettings(const MovementSettings& settings)
{
    m_settings = settings;
    qCInfo(logMovementManager) << "Настройки движения обновлены";
}

MovementSettings MovementManager::settings() const
{
    return m_settings;
}
