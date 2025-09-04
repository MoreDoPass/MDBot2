#include "GameObjectManager.h"
#include <set>  // Для отслеживания видимых GUID
#include <QLoggingCategory>

/**
 * @brief Категория логирования для GameObjectManager.
 */
Q_LOGGING_CATEGORY(logGOM, "mdbot.gom")

/**
 * @brief Конструктор.
 * @param parent Родительский QObject.
 */
GameObjectManager::GameObjectManager(QObject* parent) : QObject(parent)
{
    qCInfo(logGOM) << "GameObjectManager created.";
}

GameObjectManager::~GameObjectManager()
{
    qCInfo(logGOM) << "GameObjectManager destroyed. Clearing" << m_gameObjects.size() << "cached objects.";
    m_gameObjects.clear();
}

/**
 * @brief Обновляет внутренний кэш объектов на основе свежих данных из общей памяти.
 * @details Этот метод выполняет три действия:
 *          1. Обновляет данные для уже существующих в кэше объектов.
 *          2. Добавляет в кэш новые объекты, которых раньше не было видно.
 *          3. Удаляет из кэша объекты, которые пропали из зоны видимости.
 *          Вся сложная логика по созданию иерархии объектов удалена,
 *          теперь мы просто копируем готовую структуру GameObjectInfo.
 * @param data Структура SharedData, прочитанная из Shared Memory.
 */
void GameObjectManager::updateFromSharedMemory(const SharedData& data)
{
    try
    {
        std::set<uint64_t> visibleGuids;
        // visibleGuids.reserve(data.visibleObjectCount); // <-- ЭТА СТРОКА БЫЛА ОШИБОЧНОЙ И УДАЛЕНА

        for (int i = 0; i < data.visibleObjectCount; ++i)
        {
            const GameObjectInfo& info = data.visibleObjects[i];
            if (info.guid == 0)
            {
                continue;
            }

            visibleGuids.insert(info.guid);

            // Просто и эффективно: вставляем или обновляем GameObjectInfo в нашей карте.
            // Если объекта с таким guid нет, он будет создан. Если есть, его данные обновятся.
            m_gameObjects[info.guid] = info;
        }

        // Удаляем из нашего кэша объекты, которые больше не видны.
        // Используем стандартный идиоматический способ удаления элементов из map во время итерации.
        for (auto it = m_gameObjects.begin(); it != m_gameObjects.end();)
        {
            if (visibleGuids.find(it->first) == visibleGuids.end())
            {
                qCDebug(logGOM) << "Object removed from cache (out of sight). GUID:" << Qt::hex << it->first;
                it = m_gameObjects.erase(it);  // erase возвращает итератор на следующий элемент
            }
            else
            {
                ++it;
            }
        }
    }
    catch (const std::exception& e)
    {
        qCCritical(logGOM) << "Exception in GameObjectManager::updateFromSharedMemory:" << e.what();
    }
}

/**
 * @brief Найти объект в кэше по его уникальному идентификатору (GUID).
 * @param guid GUID искомого объекта.
 * @return Константный указатель на GameObjectInfo, если объект найден, иначе nullptr.
 */
const GameObjectInfo* GameObjectManager::getObjectByGuid(uint64_t guid) const
{
    // find() не изменяет map, поэтому его можно вызывать в const-методе
    auto it = m_gameObjects.find(guid);
    if (it != m_gameObjects.end())
    {
        // Возвращаем указатель на значение в карте
        return &it->second;
    }
    return nullptr;
}

/**
 * @brief Получить все объекты заданного типа.
 * @param type Тип искомых объектов (Unit, GameObject, Player и т.д.).
 * @return Вектор константных указателей на GameObjectInfo.
 */
std::vector<const GameObjectInfo*> GameObjectManager::getObjectsByType(GameObjectType type) const
{
    std::vector<const GameObjectInfo*> result;
    // Резервируем память, чтобы избежать многократных реалокаций,
    // хотя вряд ли объектов одного типа будет очень много.
    result.reserve(m_gameObjects.size() / 4);  // Грубое предположение
    for (const auto& pair : m_gameObjects)
    {
        // pair.second - это сам объект GameObjectInfo
        if (pair.second.type == type)
        {
            result.push_back(&pair.second);
        }
    }
    return result;
}

/**
 * @brief Получить все объекты, которые есть в кэше.
 * @return Вектор константных указателей на все закэшированные GameObjectInfo.
 */
std::vector<const GameObjectInfo*> GameObjectManager::getAllObjects() const
{
    std::vector<const GameObjectInfo*> result;
    result.reserve(m_gameObjects.size());
    for (const auto& pair : m_gameObjects)
    {
        result.push_back(&pair.second);
    }
    return result;
}