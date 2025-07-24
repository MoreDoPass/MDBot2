#include "PathfindingService.h"
#include "Logging/Logging.h"
#include "NavMeshManager.h"
#include "Bot/Movement/Pathfinder/Pathfinder.h"
#include <DetourNavMesh.h>
#include <DetourNavMeshQuery.h>

Q_LOGGING_CATEGORY(pathfindingSvc, "core.pathfindingservice")

PathfindingService& PathfindingService::getInstance()
{
    static PathfindingService instance;
    return instance;
}

// Конструктор определен как default в .h, здесь его реализация не нужна

PathfindingService::~PathfindingService()
{
    stop();
}

void PathfindingService::start(unsigned int threadCount)
{
    if (!m_workers.empty())
    {
        qCWarning(pathfindingSvc) << "Сервис уже запущен.";
        return;
    }

    m_stop = false;
    for (unsigned int i = 0; i < threadCount; ++i)
    {
        m_workers.emplace_back(&PathfindingService::workerLoop, this);
    }
    qCInfo(pathfindingSvc) << "Сервис поиска пути запущен с" << threadCount << "потоками.";
}

void PathfindingService::stop()
{
    if (m_workers.empty())
    {
        return;
    }

    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_stop = true;
    }
    m_condition.notify_all();

    qCInfo(pathfindingSvc) << "Остановка рабочих потоков...";
    for (std::thread& worker : m_workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
    m_workers.clear();
    qCInfo(pathfindingSvc) << "Все рабочие потоки остановлены.";
}

void PathfindingService::requestPath(const PathfindingRequest& request)
{
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_requests.push(request);
    }
    m_condition.notify_one();
}

void PathfindingService::workerLoop()
{
    // Создаем объекты, которые будут переиспользоваться в цикле для каждого потока
    Pathfinder pathfinder;
    dtNavMeshQuery navQuery;

    while (true)
    {
        PathfindingRequest request;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_condition.wait(lock, [this] { return m_stop || !m_requests.empty(); });

            if (m_stop && m_requests.empty())
            {
                return;
            }

            request = m_requests.front();
            m_requests.pop();
        }

        qCDebug(pathfindingSvc) << "Рабочий поток взял в обработку запрос для карты" << request.mapId;

        try
        {
            dtNavMesh* navMesh = NavMeshManager::getInstance().getNavMeshForMap(request.mapId);
            if (!navMesh)
            {
                throw std::runtime_error("Не удалось получить NavMesh для карты " + std::to_string(request.mapId));
            }

            // Инициализируем NavMeshQuery для текущего NavMesh
            if (dtStatusFailed(navQuery.init(navMesh, 2048)))
            {
                throw std::runtime_error("Не удалось инициализировать dtNavMeshQuery");
            }

            // Ищем путь
            std::vector<Vector3> path = pathfinder.findPath(&navQuery, request.startPos, request.endPos);

            // Возвращаем результат через колбэк
            if (request.callback)
            {
                // Примечание: колбэк будет выполнен в рабочем потоке.
                // Если он будет менять GUI, нужно будет использовать Qt::QueuedConnection или
                // QMetaObject::invokeMethod.
                request.callback(path);
            }
        }
        catch (const std::exception& e)
        {
            qCWarning(pathfindingSvc) << "Ошибка при обработке запроса на поиск пути:" << e.what();
            // В случае ошибки вызываем колбэк с пустым путем
            if (request.callback)
            {
                request.callback({});
            }
        }
    }
}
