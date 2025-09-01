#include "GameObjectManager.h"
#include "core/Bot/GameObjectManager/Structures/Unit.h"    // Подключаем полные определения
#include "core/Bot/GameObjectManager/Structures/Player.h"  // для создания экземпляров

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
        // Множество для хранения GUID'ов, которые пришли из DLL в этом обновлении.
        // Это нужно, чтобы потом эффективно удалить из нашего кэша те объекты,
        // которых DLL больше не видит.
        std::set<uint64_t> visibleGuids;

        // 1. Проходим по объектам из общей памяти, обновляем/добавляем их в наш кэш.
        for (int i = 0; i < data.visibleObjectCount; ++i)
        {
            const GameObjectInfo& info = data.visibleObjects[i];
            if (info.guid == 0) continue;  // Пропускаем невалидные объекты

            visibleGuids.insert(info.guid);

            auto it = m_gameObjects.find(info.guid);
            if (it == m_gameObjects.end())
            {
                // 1a. Объекта нет в кэше - создаем новый.
                // Пока что мы получаем только базовую информацию, поэтому создаем GameObject.
                // В будущем, если DLL будет передавать больше данных, здесь может быть фабрика объектов.
                auto newObject = std::make_unique<GameObject>();
                newObject->guid = info.guid;
                newObject->type = static_cast<GameObjectType>(info.type);
                newObject->position = info.position;

                qCDebug(logGOM) << "New object cached. GUID:" << Qt::hex << info.guid << Qt::dec
                                << "Type:" << info.type;
                m_gameObjects[info.guid] = std::move(newObject);
            }
            else
            {
                // 1b. Объект уже есть в кэше - просто обновляем его данные.
                it->second->type = static_cast<GameObjectType>(info.type);
                it->second->position = info.position;
            }
        }

        // 2. Удаляем из нашего кэша объекты, которые больше не видны.
        // Проходим по нашему кэшу и проверяем, есть ли GUID объекта в сете видимых.
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

GameObject* GameObjectManager::getObjectByGuid(uint64_t guid) const
{
    auto it = m_gameObjects.find(guid);
    if (it != m_gameObjects.end())
    {
        return it->second.get();
    }
    return nullptr;
}

std::vector<GameObject*> GameObjectManager::getObjectsByType(GameObjectType type) const
{
    std::vector<GameObject*> result;
    result.reserve(m_gameObjects.size());  // Небольшая оптимизация
    for (const auto& pair : m_gameObjects)
    {
        // Здесь нужно будет уточнить проверку, т.к. Player тоже является Unit
        if (pair.second && pair.second->type == type)
        {
            result.push_back(pair.second.get());
        }
    }
    return result;
}

/**
 * @brief Получить игровой объект, который сейчас в цели у игрока.
 * @details Читает указатель на цель, сохраненный хуком TargetHook,
 *          затем читает GUID цели и ищет объект в своем кэше.
 * @return Указатель на объект цели или nullptr, если цели нет или она не найдена.
 */
GameObject* GameObjectManager::getTargetObject() const
{
    // TODO: Логику получения цели также нужно будет перенести на Shared Memory.
    // DLL должна будет определять цель и класть ее GUID в специальное поле в SharedData.
    // Пока что этот метод будет возвращать nullptr.
    return nullptr;
}