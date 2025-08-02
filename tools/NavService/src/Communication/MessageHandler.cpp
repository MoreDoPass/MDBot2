#include "MessageHandler.h"
#include "Utils/Logger.h"
#include "Navigation/NavMeshManager.h"
#include "Pathfinder/Pathfinder.h"  // <<< НОВОЕ: Подключаем Pathfinder
#include <DetourNavMeshQuery.h>     // <<< НОВОЕ: Нужно для создания объекта запроса
#include <memory>                   // <<< ДОБАВЬТЕ ЭТО, если еще не добавлено

// --- Реализация функций конвертации ---

void to_json(json& j, const Vector3& v)
{
    j = json::array({v.x, v.y, v.z});
}

void from_json(const json& j, Vector3& v)
{
    j.at(0).get_to(v.x);
    j.at(1).get_to(v.y);
    j.at(2).get_to(v.z);
}

void to_json(json& j, const PathRequestData& d)
{
    j = json{{"map_id", d.map_id}, {"start", d.start}, {"end", d.end}};
}

void from_json(const json& j, PathRequestData& d)
{
    j.at("map_id").get_to(d.map_id);
    j.at("start").get_to(d.start);
    j.at("end").get_to(d.end);
}

void to_json(json& j, const PathRequest& r)
{
    // В исходящем JSON у нас нет 'action', поэтому не добавляем
    j = json{{"request_id", r.request_id}, {"data", r.data}};
}

void from_json(const json& j, PathRequest& r)
{
    // 'action' проверяется отдельно, здесь не нужен
    j.at("request_id").get_to(r.request_id);
    j.at("data").get_to(r.data);
}

float calculateTotalDistance(const std::vector<Vector3>& path)
{
    float distance = 0.0f;
    if (path.size() < 2)
    {
        return distance;
    }
    for (size_t i = 0; i < path.size() - 1; ++i)
    {
        distance += path[i].distance(path[i + 1]);
    }
    return distance;
}
// --- Реализация самого класса ---

MessageHandler::MessageHandler(NavMeshManager* navMeshManager, Pathfinder* pathfinder, QObject* parent)
    : QObject(parent), m_navMeshManager(navMeshManager), m_pathfinder(pathfinder)
{
    if (!m_navMeshManager)
    {
        qCCritical(navService) << "MessageHandler created with a null NavMeshManager!";
    }
    if (!m_pathfinder)
    {
        qCCritical(navService) << "MessageHandler created with a null Pathfinder!";
    }
    qCDebug(navService) << "MessageHandler created.";
}

void MessageHandler::handleRequest(quint64 clientId, QString requestJson)
{
    qCDebug(navService) << "Handling request from client" << clientId;
    json response;
    uint64_t requestId = 0;

    try
    {
        json request = json::parse(requestJson.toStdString());
        requestId = request.value("request_id", 0);

        if (!request.contains("action") || request.at("action") != "find_path")
        {
            throw std::runtime_error("Invalid or missing 'action'. Must be 'find_path'.");
        }

        PathRequest req = request.get<PathRequest>();
        qCInfo(navService) << "Processing find_path for map" << req.data.map_id;

        // === НАЧАЛО ИНТЕГРАЦИИ PATHFINDER ===

        if (!m_navMeshManager || !m_pathfinder)
        {
            throw std::runtime_error("NavMeshManager or Pathfinder is not available.");
        }

        // 1. Получаем NavMesh для нужной карты
        dtNavMesh* navMesh = m_navMeshManager->getNavMeshForMap(req.data.map_id);
        if (!navMesh)
        {
            throw std::runtime_error("Failed to get NavMesh for map: " + std::to_string(req.data.map_id));
        }

        // 2. Убеждаемся, что все нужные тайлы загружены.
        m_navMeshManager->ensureTilesLoaded(req.data.map_id, req.data.start, req.data.end);
        qCDebug(navService) << "Required tiles are loaded.";

        auto navQuery = std::make_unique<dtNavMeshQuery>();
        if (!navQuery)
        {
            throw std::runtime_error("Failed to allocate dtNavMeshQuery.");
        }

        // Инициализируем его через указатель
        dtStatus status = navQuery->init(navMesh, 2048);
        if (dtStatusFailed(status))
        {
            throw std::runtime_error("Failed to initialize dtNavMeshQuery. Status: " + std::to_string(status));
        }

        // 4. Ищем путь!
        // В Pathfinder передаем сырой указатель с помощью .get()
        std::vector<Vector3> path = m_pathfinder->findPath(navQuery.get(), req.data.start, req.data.end);
        // 5. Формируем ответ в зависимости от результата
        if (path.empty())
        {
            // Путь не найден
            response["status"] = "error";
            response["request_id"] = req.request_id;
            response["error"]["code"] = "PATH_NOT_FOUND";
            response["error"]["message"] = "Не удалось найти путь между указанными точками";
        }
        else
        {
            // Путь найден
            response["status"] = "success";
            response["request_id"] = req.request_id;
            response["data"]["path"] = path;  // nlohmann/json сам обработает vector<Vector3>
            response["data"]["path_length"] = path.size();
            response["data"]["total_distance"] = calculateTotalDistance(path);
        }
    }
    catch (const json::exception& e)
    {
        qCCritical(navService) << "JSON processing error:" << e.what();
        response["status"] = "error";
        response["request_id"] = requestId;
        response["error"]["code"] = "INVALID_JSON_DATA";
        response["error"]["message"] = e.what();
    }
    catch (const std::exception& e)
    {
        qCCritical(navService) << "Generic error during request handling:" << e.what();
        response["status"] = "error";
        response["request_id"] = requestId;
        response["error"]["code"] = "INTERNAL_ERROR";
        response["error"]["message"] = e.what();
    }

    emit responseReady(clientId, QString::fromStdString(response.dump()));
}