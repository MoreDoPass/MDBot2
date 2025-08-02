#pragma once

#include <QObject>
#include <QString>
#include "Utils/Vector.h"  // Убедитесь, что путь к вашему Vector.h правильный
#include <vector>

// === НАЧАЛО МАГИИ nlohmann/json ===
// Подключаем библиотеку JSON
#include <nlohmann/json.hpp>

// Для удобства
using json = nlohmann::json;

// --- Структуры данных для запросов и ответов ---
// Они точно соответствуют вашему протоколу
class NavMeshManager;
class Pathfinder;

struct PathRequestData
{
    uint32_t map_id;
    Vector3 start;
    Vector3 end;
};

struct PathRequest
{
    uint64_t request_id;
    PathRequestData data;
};

// --- Функции для автоматической конвертации C++ <-> JSON ---
// Это суперсила nlohmann/json. Мы описываем, как наши структуры
// должны превращаться в JSON и обратно.

void to_json(json& j, const Vector3& v);
void from_json(const json& j, Vector3& v);

void to_json(json& j, const PathRequestData& d);
void from_json(const json& j, PathRequestData& d);

void to_json(json& j, const PathRequest& r);
void from_json(const json& j, PathRequest& r);
// === КОНЕЦ МАГИИ ===

/**
 * @class MessageHandler
 * @brief Разбирает входящие JSON-запросы, используя nlohmann/json,
 *        и формирует JSON-ответы.
 */
class MessageHandler : public QObject
{
    Q_OBJECT

   public:
    explicit MessageHandler(NavMeshManager* navMeshManager, Pathfinder* pathfinder, QObject* parent = nullptr);

   public slots:
    /**
     * @brief Основной слот для обработки входящего запроса.
     * @param clientId ID клиента, от которого пришел запрос.
     * @param requestJson Сырая строка с JSON-запросом.
     */
    void handleRequest(quint64 clientId, QString requestJson);

   signals:
    /**
     * @brief Сигнал, испускаемый, когда ответ готов к отправке.
     * @param clientId ID клиента, которому предназначен ответ.
     * @param responseJson Готовая строка с JSON-ответом.
     */
    void responseReady(quint64 clientId, const QString& responseJson);

   private:
    NavMeshManager* m_navMeshManager;
    Pathfinder* m_pathfinder;
};