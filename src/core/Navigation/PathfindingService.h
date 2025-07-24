#pragma once

#include "Utils/Vector.h"
#include <vector>
#include <functional>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

/**
 * @struct PathfindingRequest
 * @brief Структура, описывающая запрос на поиск пути.
 */
struct PathfindingRequest
{
    uint32_t mapId;                                      ///< ID карты для поиска пути.
    Vector3 startPos;                                    ///< Начальная точка.
    Vector3 endPos;                                      ///< Конечная точка.
    std::function<void(std::vector<Vector3>)> callback;  ///< Функция, которая будет вызвана с результатом.
};

/**
 * @class PathfindingService
 * @brief Потокобезопасный сервис для асинхронного поиска пути.
 *
 * Управляет пулом потоков, которые обрабатывают запросы на поиск пути из очереди.
 * Позволяет основной логике приложения не блокироваться в ожидании результата.
 */
class PathfindingService
{
   public:
    static PathfindingService& getInstance();

    /**
     * @brief Запускает рабочие потоки сервиса.
     * @param threadCount - Количество создаваемых потоков.
     */
    void start(unsigned int threadCount = 4);

    /**
     * @brief Останавливает рабочие потоки и очищает очередь.
     */
    void stop();

    /**
     * @brief Добавляет новый запрос на поиск пути в очередь.
     * @param request - Запрос на поиск пути.
     */
    void requestPath(const PathfindingRequest& request);

   private:
    PathfindingService() = default;
    ~PathfindingService();

    PathfindingService(const PathfindingService&) = delete;
    PathfindingService& operator=(const PathfindingService&) = delete;

    /**
     * @brief Функция, выполняемая в каждом рабочем потоке.
     */
    void workerLoop();

    std::queue<PathfindingRequest> m_requests;  ///< Очередь запросов.
    std::mutex m_mutex;                         ///< Мьютекс для защиты очереди.
    std::condition_variable m_condition;        ///< Условная переменная для пробуждения потоков.
    std::vector<std::thread> m_workers;         ///< Пул рабочих потоков.
    bool m_stop = false;                        ///< Флаг для остановки потоков.
};
