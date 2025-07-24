#include "MovementManager.h"
#include "core/Bot/Movement/CtM/CtMEnablerHook.h"
#include <QLoggingCategory>
#include "core/Navigation/PathfindingService.h"
#include "core/Bot/Character/Character.h"  // Предполагается, что у нас есть доступ к Character для получения текущей позиции

Q_LOGGING_CATEGORY(logMovementManager, "mdbot.movementmanager")

MovementManager::MovementManager(MemoryManager* memory, QObject* parent)
    : QObject(parent), m_ctm(std::make_unique<CtmExecutor>(memory))
{
    qCInfo(logMovementManager) << "MovementManager создан";

    connect(&m_pathExecutorTimer, &QTimer::timeout, this, &MovementManager::updatePathExecution);

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

    // TODO: Получить текущую позицию персонажа.
    // Пока что используем заглушку. В реальном коде это будет что-то вроде
    // Vector3 currentPos = m_character->getPosition();
    Vector3 currentPos(0, 0, 0);

    qCInfo(logMovementManager) << "Запрос на поиск пути от" << currentPos.x << currentPos.y << currentPos.z << "до" << x
                               << y << z;

    PathfindingRequest request;
    request.mapId = 0;  // TODO: Получить актуальный MapID
    request.startPos = currentPos;
    request.endPos = {x, y, z};

    // Используем QMetaObject::invokeMethod для потокобезопасного вызова onPathFound
    // из рабочего потока PathfindingService в потоке MovementManager.
    request.callback = [this](std::vector<Vector3> path)
    {
        QMetaObject::invokeMethod(
            this, [this, path = std::move(path)]() { onPathFound(std::move(path)); }, Qt::QueuedConnection);
    };

    PathfindingService::getInstance().requestPath(request);

    return true;  // Запрос успешно отправлен
}

void MovementManager::stop()
{
    // TODO: реализовать остановку движения (CtM IDLE или другое действие)
    qCInfo(logMovementManager) << "Остановка движения (stop)";
    m_pathExecutorTimer.stop();
    // Например, можно вызвать CtM с action NONE или IDLE
    m_ctm->moveTo(0, 0, 0, 0.1f);  // Пример: CtM в текущую позицию с минимальной дистанцией
    m_currentPath.clear();
    m_currentPathIndex = -1;
}

void MovementManager::onPathFound(std::vector<Vector3> path)
{
    if (path.empty())
    {
        qCWarning(logMovementManager) << "Путь не найден или пуст.";
        m_currentPath.clear();
        m_currentPathIndex = -1;
        m_pathExecutorTimer.stop();
        return;
    }

    qCInfo(logMovementManager) << "Путь успешно найден. Точек:" << path.size() << ". Начинаем движение.";
    m_currentPath = std::move(path);
    m_currentPathIndex = 0;

    const auto& nextPoint = m_currentPath[m_currentPathIndex];
    m_ctm->moveTo(nextPoint.x, nextPoint.y, nextPoint.z, m_settings.ctmDistance);

    m_pathExecutorTimer.start(250);  // Проверяем каждые 250 мс
}

void MovementManager::updatePathExecution()
{
    if (m_currentPath.empty() || m_currentPathIndex < 0)
    {
        return;  // Нет активного пути
    }

    // TODO: Получить актуальную позицию персонажа
    Vector3 currentPos(0, 0, 0);
    const auto& targetPoint = m_currentPath[m_currentPathIndex];

    // Простая проверка дистанции (в 2D, без учета Z)
    const float dx = currentPos.x - targetPoint.x;
    const float dy = currentPos.y - targetPoint.y;
    const float distanceSq = dx * dx + dy * dy;

    // Считаем, что точка достигнута, если мы достаточно близко
    if (distanceSq < (m_settings.ctmDistance * m_settings.ctmDistance))
    {
        m_currentPathIndex++;
        if (m_currentPathIndex >= m_currentPath.size())
        {
            // Путь завершен
            qCInfo(logMovementManager) << "Цель достигнута. Путь завершен.";
            stop();
        }
        else
        {
            // Движемся к следующей точке
            const auto& nextPoint = m_currentPath[m_currentPathIndex];
            qCDebug(logMovementManager) << "Движемся к следующей точке пути #" << m_currentPathIndex;
            m_ctm->moveTo(nextPoint.x, nextPoint.y, nextPoint.z, m_settings.ctmDistance);
        }
    }
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
