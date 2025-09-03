#include "GameObjectManager.h"

#include <set>  // Для отслеживания видимых GUID

/**
 * @brief Категория логирования для GameObjectManager.
 */
Q_LOGGING_CATEGORY(logGOM, "mdbot.gom")

// === СМЕЩЕНИЯ ДЛЯ ОБХОДА СПИСКА ОБЪЕКТОВ ===
// ВАЖНО: Эти значения нужно найти для вашего клиента игры!
namespace ObjectManagerOffsets
{
/// @brief Смещение до указателя на следующий объект в связном списке.
constexpr int32_t NextObject = 0x3C;
/// @brief Смещение до GUID объекта от его базового адреса.
constexpr int32_t Guid = 0x30;
/// @brief Смещение до типа объекта от его базового адреса.
constexpr int32_t Type = 0x14;
}  // namespace ObjectManagerOffsets

GameObjectManager::GameObjectManager(MemoryManager* memoryManager, QObject* parent)
    : QObject(parent), m_memoryManager(memoryManager)
{
    if (!m_memoryManager)
    {
        // Использование qFatal здесь оправдано, так как без MemoryManager
        // дальнейшая работа невозможна и это критическая ошибка конфигурации.
        qFatal("GameObjectManager created with nullptr MemoryManager!");
    }
    qCInfo(logGOM) << "GameObjectManager created.";
}

GameObjectManager::~GameObjectManager()
{
    qCInfo(logGOM) << "GameObjectManager destroyed. Clearing" << m_gameObjects.size() << "cached objects.";
    m_gameObjects.clear();  // unique_ptr сам удалит все объекты
}

void GameObjectManager::updateFromSharedMemory(const SharedData& data)
{
    try
    {
        std::set<uint64_t> visibleGuids;

        for (int i = 0; i < data.visibleObjectCount; ++i)
        {
            const GameObjectInfo& info = data.visibleObjects[i];
            if (info.guid == 0) continue;

            visibleGuids.insert(info.guid);

            auto it = m_gameObjects.find(info.guid);
            if (it == m_gameObjects.end())
            {
                // --- ОБЪЕКТА НЕТ В КЭШЕ - СОЗДАЕМ И ЗАПОЛНЯЕМ ---
                std::unique_ptr<WorldObject> newObject = nullptr;
                const GameObjectType type = static_cast<GameObjectType>(info.type);

                // Фабрика объектов: создаем экземпляр нужного класса
                switch (type)
                {
                    case GameObjectType::Player:
                        newObject = std::make_unique<Player>();
                        break;
                    case GameObjectType::Unit:
                        newObject = std::make_unique<Unit>();
                        break;
                    case GameObjectType::GameObject:
                        newObject = std::make_unique<GameObject>();
                        break;
                    default:
                        newObject = std::make_unique<WorldObject>();
                        break;
                }

                if (newObject)
                {
                    // --- ПОЛНОЕ КОПИРОВАНИЕ ДАННЫХ ИЗ SHARED MEMORY ---
                    newObject->guid = info.guid;
                    newObject->objectType = type;

                    // Копируем позицию и другие специфичные для типа данные.
                    // Используем static_cast, так как мы точно знаем тип из 'info.type'.
                    switch (type)
                    {
                        case GameObjectType::Player:
                            static_cast<Player*>(newObject.get())->position = info.position;
                            // TODO: Копировать здоровье, ману и т.д. для игроков
                            break;
                        case GameObjectType::Unit:
                            static_cast<Unit*>(newObject.get())->position = info.position;
                            // TODO: Копировать здоровье, ману и т.д. для юнитов
                            break;
                        case GameObjectType::GameObject:
                            static_cast<GameObject*>(newObject.get())->position = info.position;
                            break;
                        default:
                            // Для WorldObject и других типов без позиции ничего не делаем
                            break;
                    }

                    qCDebug(logGOM) << "New object cached. GUID:" << Qt::hex << info.guid << Qt::dec
                                    << "Type:" << static_cast<uint32_t>(info.type);
                    m_gameObjects[info.guid] = std::move(newObject);
                }
            }
            else
            {
                // --- ОБЪЕКТ УЖЕ ЕСТЬ В КЭШЕ - ОБНОВЛЯЕМ ЕГО ДАННЫЕ ---
                WorldObject* existingObject = it->second.get();

                // Обновляем позицию и другие поля, которые могут меняться
                switch (existingObject->objectType)
                {
                    case GameObjectType::Player:
                        static_cast<Player*>(existingObject)->position = info.position;
                        break;
                    case GameObjectType::Unit:
                        static_cast<Unit*>(existingObject)->position = info.position;
                        break;
                    case GameObjectType::GameObject:
                        static_cast<GameObject*>(existingObject)->position = info.position;
                        break;
                    default:
                        break;
                }
            }
        }

        // Удаляем из нашего кэша объекты, которые больше не видны.
        for (auto it = m_gameObjects.begin(); it != m_gameObjects.end();)
        {
            if (visibleGuids.find(it->first) == visibleGuids.end())
            {
                qCDebug(logGOM) << "Object removed from cache (out of sight). GUID:" << Qt::hex << it->first;
                it = m_gameObjects.erase(it);
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

WorldObject* GameObjectManager::getObjectByGuid(uint64_t guid) const
{
    auto it = m_gameObjects.find(guid);
    if (it != m_gameObjects.end())
    {
        return it->second.get();
    }
    return nullptr;
}

std::vector<WorldObject*> GameObjectManager::getObjectsByType(GameObjectType type) const
{
    std::vector<WorldObject*> result;
    result.reserve(m_gameObjects.size());
    for (const auto& pair : m_gameObjects)
    {
        if (pair.second && pair.second->objectType == type)
        {
            result.push_back(pair.second.get());
        }
    }
    return result;
}

WorldObject* GameObjectManager::getTargetObject() const
{
    return nullptr;
}