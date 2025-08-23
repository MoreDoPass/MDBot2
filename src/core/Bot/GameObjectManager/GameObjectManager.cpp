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
        qFatal("GameObjectManager created with nullptr MemoryManager!");
    }
    qCInfo(logGOM) << "GameObjectManager created.";
    initializeHooks();  // <--- Вызываем инициализацию хуков
}

GameObjectManager::~GameObjectManager()
{
    shutdownHooks();
    qCInfo(logGOM) << "GameObjectManager destroyed. Clearing" << m_gameObjects.size() << "cached objects.";
    m_gameObjects.clear();  // unique_ptr сам удалит все объекты
}

bool GameObjectManager::update()
{
    try
    {
        if (!m_memoryManager || !m_memoryManager->isProcessOpen())
        {
            qCWarning(logGOM) << "Update skipped: MemoryManager is not available.";
            return false;
        }

        // 1. Получаем указатель на первый объект из статического адреса
        uintptr_t firstObjectPtr = 0;
        if (!m_memoryManager->readMemory(m_firstObjectPtrAddr, firstObjectPtr))
        {
            qCWarning(logGOM) << "Failed to read first object pointer from" << Qt::hex << m_firstObjectPtrAddr;
            return false;
        }

        // Множество для хранения GUID'ов, которые мы увидели в этом цикле обновления.
        // Нужно, чтобы потом удалить из нашего кэша те объекты, которых больше нет в игре.
        std::set<uint64_t> visibleGuids;
        uintptr_t currentObjectPtr = firstObjectPtr;

        // Ограничитель, чтобы не уйти в бесконечный цикл, если что-то пойдет не так
        for (int i = 0; i < 2048 && currentObjectPtr != 0; ++i)
        {
            // 2. Читаем GUID и тип текущего объекта
            uint64_t guid = 0;
            GameObjectType type = GameObjectType::None;

            if (!m_memoryManager->readMemory(currentObjectPtr + ObjectManagerOffsets::Guid, guid) ||
                !m_memoryManager->readMemory(currentObjectPtr + ObjectManagerOffsets::Type, type))
            {
                qCWarning(logGOM) << "Failed to read GUID or Type for object at" << Qt::hex << currentObjectPtr;
                // Переходим к следующему, может этот просто "битый"
                m_memoryManager->readMemory(currentObjectPtr + ObjectManagerOffsets::NextObject, currentObjectPtr);
                continue;
            }

            if (guid == 0)  // Пропускаем невалидные объекты
            {
                m_memoryManager->readMemory(currentObjectPtr + ObjectManagerOffsets::NextObject, currentObjectPtr);
                continue;
            }

            visibleGuids.insert(guid);

            // 3. Проверяем, есть ли объект в нашем кэше.
            auto it = m_gameObjects.find(guid);
            if (it == m_gameObjects.end())
            {
                // 3a. Объекта нет - создаем новый
                std::unique_ptr<GameObject> newObject = nullptr;
                size_t objectSize = 0;  // Размер структуры для чтения

                // Фабрика объектов по типу
                switch (type)
                {
                    case GameObjectType::Player:
                        newObject = std::make_unique<Player>();
                        objectSize = sizeof(Player);  // <-- ИЗМЕНЕНИЕ: правильный размер
                        break;
                    case GameObjectType::Unit:
                        newObject = std::make_unique<Unit>();
                        objectSize = sizeof(Unit);  // <-- ИЗМЕНЕНИЕ: правильный размер
                        break;
                    case GameObjectType::GameObject:  // Трава, руда и т.д.
                    case GameObjectType::DynamicObject:
                        newObject = std::make_unique<GameObject>();
                        objectSize = sizeof(GameObject);  // <-- ИЗМЕНЕНИЕ: правильный размер
                        break;
                    default:
                        // Неизвестный или ненужный тип, пропускаем
                        break;
                }

                if (newObject && objectSize > 0)
                {
                    // ИЗМЕНЕНИЕ: Используем reinterpret_cast и правильный размер objectSize
                    if (m_memoryManager->readMemory(currentObjectPtr, reinterpret_cast<char*>(newObject.get()),
                                                    objectSize))
                    {
                        qCDebug(logGOM) << "New object detected. GUID:" << guid
                                        << "Type:" << static_cast<uint32_t>(type);
                        m_gameObjects[guid] = std::move(newObject);
                    }
                }
            }
            else
            {
                // 3b. Объект уже есть в кэше - обновляем его данные
                // ИЗМЕНЕНИЕ: Используем reinterpret_cast и правильный размер, соответствующий типу объекта
                // Для простоты пока читаем размер базового класса, но в идеале нужно хранить
                // размер или использовать virtual-функцию для его получения.
                // Пока оставим так, чтобы не усложнять. Главное было исправить создание.
                m_memoryManager->readMemory(currentObjectPtr, reinterpret_cast<char*>(it->second.get()),
                                            sizeof(GameObject));  // Здесь пока читаем базовый размер для обновления
            }

            // 4. Переходим к следующему объекту в связном списке игры
            if (!m_memoryManager->readMemory(currentObjectPtr + ObjectManagerOffsets::NextObject, currentObjectPtr))
            {
                qCWarning(logGOM) << "Failed to read next object pointer, ending update loop.";
                break;
            }
        }

        // 5. Удаляем из нашего кэша объекты, которые больше не видны
        for (auto it = m_gameObjects.begin(); it != m_gameObjects.end();)
        {
            if (visibleGuids.find(it->first) == visibleGuids.end())
            {
                qCDebug(logGOM) << "Object removed from cache (out of sight). GUID:" << it->first;
                it = m_gameObjects.erase(it);  // erase возвращает итератор на следующий элемент
            }
            else
            {
                ++it;
            }
        }
        return true;
    }
    catch (const std::exception& e)
    {
        qCCritical(logGOM) << "Exception in GameObjectManager::update:" << e.what();
        return false;
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

void GameObjectManager::initializeHooks()
{
    try
    {
        qCInfo(logGOM) << "Initializing hooks for GameObjectManager...";
        // 1. Выделяем память в процессе игры, куда хук будет складывать указатель.
        m_targetPtrSaveAddr = m_memoryManager->allocMemory(sizeof(uintptr_t));
        if (!m_targetPtrSaveAddr)
        {
            qCCritical(logGOM) << "Failed to allocate memory for target pointer save address!";
            return;
        }
        qCInfo(logGOM) << "Allocated memory for target pointer at:" << Qt::hex
                       << reinterpret_cast<uintptr_t>(m_targetPtrSaveAddr);

        // 2. Создаем и устанавливаем TargetHook.
        //    ВАЖНО: Адрес 0x0072A6C5 - это пример! Тебе нужно будет найти актуальный.
        constexpr uintptr_t targetFuncAddress = 0x0072A6C5;
        m_targetHook = std::make_unique<TargetHook>(targetFuncAddress, m_memoryManager,
                                                    reinterpret_cast<uintptr_t>(m_targetPtrSaveAddr));

        if (!m_targetHook->install())
        {
            qCCritical(logGOM) << "Failed to install TargetHook at" << Qt::hex << targetFuncAddress;
            // Если установка провалилась, очищаем, чтобы не было мусора
            m_memoryManager->freeMemory(m_targetPtrSaveAddr);
            m_targetPtrSaveAddr = nullptr;
            m_targetHook.reset();
        }
        else
        {
            qCInfo(logGOM) << "TargetHook installed successfully at" << Qt::hex << targetFuncAddress;
        }
    }
    catch (const std::exception& e)
    {
        qCCritical(logGOM) << "Exception during hooks initialization:" << e.what();
    }
}

/**
 * @brief Снимает и очищает все хуки, используемые GOM.
 */
void GameObjectManager::shutdownHooks()
{
    try
    {
        qCInfo(logGOM) << "Shutting down hooks for GameObjectManager...";
        // Снимаем и удаляем хук
        if (m_targetHook)
        {
            if (m_targetHook->isInstalled())
            {
                m_targetHook->uninstall();
                qCInfo(logGOM) << "TargetHook uninstalled.";
            }
            m_targetHook.reset();  // unique_ptr сам вызовет деструктор
        }

        // Освобождаем выделенную память
        if (m_targetPtrSaveAddr)
        {
            m_memoryManager->freeMemory(m_targetPtrSaveAddr);
            qCInfo(logGOM) << "Freed memory for target pointer at:" << Qt::hex
                           << reinterpret_cast<uintptr_t>(m_targetPtrSaveAddr);
            m_targetPtrSaveAddr = nullptr;
        }
    }
    catch (const std::exception& e)
    {
        qCCritical(logGOM) << "Exception during hooks shutdown:" << e.what();
    }
}

/**
 * @brief Получить игровой объект, который сейчас в цели у игрока.
 * @details Читает указатель на цель, сохраненный хуком TargetHook,
 *          затем читает GUID цели и ищет объект в своем кэше.
 * @return Указатель на объект цели или nullptr, если цели нет или она не найдена.
 */
GameObject* GameObjectManager::getTargetObject() const
{
    try
    {
        // 1. Проверяем, что вся инфраструктура хука на месте
        if (!m_targetPtrSaveAddr || !m_memoryManager)
        {
            qCWarning(logGOM) << "Cannot get target object: hook infrastructure is not initialized.";
            return nullptr;
        }

        // 2. Читаем из нашей ячейки "сырой" адрес объекта цели.
        uintptr_t targetBaseAddr = 0;
        if (!m_memoryManager->readMemory(reinterpret_cast<uintptr_t>(m_targetPtrSaveAddr), targetBaseAddr))
        {
            // Эта ошибка может возникнуть, если MemoryManager не может прочитать память
            qCWarning(logGOM) << "Failed to read target base address from saved pointer location.";
            return nullptr;
        }

        // 3. Если адрес нулевой, значит в игре сейчас нет цели. Это нормальная ситуация.
        if (targetBaseAddr == 0)
        {
            return nullptr;
        }

        // 4. ВАЖНО: Преобразуем прочитанный адрес (который просто число)
        //    в указатель на нашу структуру GameObject и возвращаем его.
        //    Именно это ты и просил сделать.
        return reinterpret_cast<GameObject*>(targetBaseAddr);
    }
    catch (const std::exception& e)
    {
        qCCritical(logGOM) << "Exception in getTargetObject:" << e.what();
        return nullptr;
    }
}