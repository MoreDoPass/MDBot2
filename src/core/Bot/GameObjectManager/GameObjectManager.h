#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>
#include "core/MemoryManager/MemoryManager.h"
#include "core/Bot/GameObjectManager/Structures/GameObject.h"  // Подключаем базовую структуру
#include "Target/TargetHook.h"

// Прямые объявления, чтобы не включать лишние заголовки
struct Unit;
struct Player;

/**
 * @brief Категория логирования для GameObjectManager.
 */
Q_DECLARE_LOGGING_CATEGORY(logGOM)

/**
 * @class GameObjectManager
 * @brief Управляет списком видимых игровых объектов.
 * @details Отвечает за чтение объектного менеджера из памяти игры,
 *          обновление кэша объектов (игроки, NPC, ресурсы и т.д.)
 *          и предоставление доступа к ним.
 */
class GameObjectManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор.
     * @param memoryManager Указатель на менеджер памяти для доступа к процессу.
     * @param parent Родительский QObject.
     */
    explicit GameObjectManager(MemoryManager* memoryManager, QObject* parent = nullptr);

    /**
     * @brief Деструктор.
     */
    ~GameObjectManager() override;

    /**
     * @brief Обновляет список объектов из памяти игры.
     * @details Этот метод должен вызываться в основном цикле бота.
     *          Он проходит по списку объектов в памяти, добавляет новые,
     *          обновляет существующие и удаляет те, что больше не видны.
     * @return true, если обновление прошло успешно.
     */
    bool update();

    /**
     * @brief Получить объект по его GUID.
     * @param guid Уникальный идентификатор объекта.
     * @return Указатель на объект или nullptr, если объект не найден.
     */
    GameObject* getObjectByGuid(uint64_t guid) const;

    /**
     * @brief Получить все объекты заданного типа.
     * @param type Тип искомых объектов.
     * @return Вектор указателей на найденные объекты.
     */
    std::vector<GameObject*> getObjectsByType(GameObjectType type) const;

    /**
     * @brief Получить игровой объект, который сейчас в цели у игрока.
     * @details Читает указатель на цель, сохраненный хуком TargetHook,
     *          затем читает GUID цели и ищет объект в своем кэше.
     * @return Указатель на объект цели или nullptr, если цели нет или она не найдена.
     */
    GameObject* getTargetObject() const;

   private:
    /**
     * @brief Инициализирует и устанавливает все необходимые хуки для GOM.
     */
    void initializeHooks();

    /**
     * @brief Снимает и очищает все хуки, используемые GOM.
     */
    void shutdownHooks();

    /**
     * @brief Умный указатель на наш хук для получения цели.
     * @details unique_ptr гарантирует, что объект хука будет корректно удален.
     */
    std::unique_ptr<TargetHook> m_targetHook;

    /**
     * @brief Адрес в памяти игры, куда TargetHook сохраняет указатель на объект цели.
     * @details Мы сами выделяем эту память при инициализации.
     */
    void* m_targetPtrSaveAddr = nullptr;

    /// @brief Менеджер памяти для чтения данных из процесса.
    MemoryManager* m_memoryManager;

    /**
     * @brief Адрес указателя на первый объект в связном списке менеджера объектов игры.
     * @warning Это значение нужно найти с помощью Cheat Engine / IDA Pro!
     */
    const uintptr_t m_firstObjectPtrAddr = 0x00B41420;  // ПРИМЕР!

    /**
     * @brief Кэш игровых объектов. Ключ - GUID.
     * @details Используем std::unique_ptr для автоматического управления памятью объектов.
     */
    std::map<uint64_t, std::unique_ptr<GameObject>> m_gameObjects;
};