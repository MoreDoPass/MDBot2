#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>
#include "core/MemoryManager/MemoryManager.h"
#include "core/Bot/GameObjectManager/Structures/GameObject.h"
#include "Shared/Data/SharedData.h"  // <-- Подключаем "контракт" данных

Q_DECLARE_LOGGING_CATEGORY(logGOM)

/**
 * @class GameObjectManager
 * @brief Управляет кэшем игровых объектов на основе данных из Shared Memory.
 * @details Больше не читает память игры напрямую для обхода списка. Вместо этого
 *          получает готовые данные от класса Bot и обновляет свой внутренний кэш.
 */
class GameObjectManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор.
     * @param memoryManager Указатель на менеджер памяти (может быть нужен для чтения доп. полей).
     * @param parent Родительский QObject.
     */
    explicit GameObjectManager(MemoryManager* memoryManager, QObject* parent = nullptr);
    ~GameObjectManager() override;

    /**
     * @brief Обновляет кэш объектов на основе данных, полученных из DLL.
     * @param data Структура SharedData, прочитанная из общей памяти.
     */
    void updateFromSharedMemory(const SharedData& data);

    /**
     * @brief Получить объект из кэша по его GUID.
     * @param guid Уникальный идентификатор объекта.
     * @return Указатель на объект или nullptr, если объект не найден в кэше.
     */
    GameObject* getObjectByGuid(uint64_t guid) const;

    /**
     * @brief Получить все объекты заданного типа из кэша.
     * @param type Тип искомых объектов.
     * @return Вектор указателей на найденные объекты.
     */
    std::vector<GameObject*> getObjectsByType(GameObjectType type) const;

    /**
     * @brief Получить игровой объект, который сейчас в цели у игрока.
     * @return Указатель на объект цели или nullptr.
     * @note Логика этого метода будет реализована позже, когда DLL научится передавать GUID цели.
     */
    GameObject* getTargetObject() const;

   private:
    /// @brief Менеджер памяти для чтения данных из процесса.
    MemoryManager* m_memoryManager;

    /**
     * @brief Кэш игровых объектов. Ключ - GUID.
     * @details Используем std::unique_ptr для автоматического управления памятью объектов.
     */
    std::map<uint64_t, std::unique_ptr<GameObject>> m_gameObjects;
};