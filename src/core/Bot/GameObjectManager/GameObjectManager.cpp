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

bool GameObjectManager::unitHasAura(uint64_t guid, int32_t spellId) const
{
    // 1. Находим объект в нашем кэше
    const GameObjectInfo* info = getObjectByGuid(guid);
    if (!info)
    {
        return false;  // Если объекта нет, то и аур у него нет
    }

    // 2. В простом цикле ищем нужный ID в массиве аур
    for (int i = 0; i < info->auraCount; ++i)
    {
        if (info->auras[i] == spellId)
        {
            return true;  // Нашли!
        }
    }

    // 3. Если цикл завершился, а мы ничего не нашли
    return false;
}

bool GameObjectManager::isUnitInCombat(uint64_t guid) const
{
    const GameObjectInfo* info = getObjectByGuid(guid);
    if (info)
    {
        // Проверяем 19-й бит (маска 0x80000)
        return (info->flags & 0x80000) != 0;
    }
    return false;  // Если объекта нет в кэше, он точно не в бою
}

uint64_t GameObjectManager::getUnitTargetGuid(uint64_t guid) const
{
    // 1. Находим объект в нашем кэше
    const GameObjectInfo* info = getObjectByGuid(guid);

    // 2. Если объект найден, возвращаем значение его поля targetGuid
    if (info)
    {
        return info->targetGuid;
    }

    // 3. Если объект не найден, у него не может быть цели
    return 0;
}

bool GameObjectManager::isUnitCasting(uint64_t unitGuid) const
{
    const GameObjectInfo* unit = getObjectByGuid(unitGuid);
    if (unit)
    {
        return unit->isCasting;
    }
    return false;  // Если юнит не найден, считаем, что он не кастует.
}

uint32_t GameObjectManager::getUnitCastingSpellId(uint64_t unitGuid) const
{
    const GameObjectInfo* unit = getObjectByGuid(unitGuid);
    if (unit)
    {
        return unit->castingSpellId;
    }
    return 0;  // Если юнит не найден, возвращаем 0.
}