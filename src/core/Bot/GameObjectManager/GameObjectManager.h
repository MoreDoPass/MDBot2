#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <cstdint>
#include <map>
#include <vector>
#include "Shared/Data/SharedData.h"  // <-- КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: Теперь работаем напрямую с этой структурой

/**
 * @brief Категория логирования для GameObjectManager.
 */
Q_DECLARE_LOGGING_CATEGORY(logGOM)

/**
 * @class GameObjectManager
 * @brief "Глаза" бота. Кэширует и предоставляет доступ к информации об игровых объектах.
 * @details Этот менеджер получает "сырые" данные об объектах из общей памяти (в виде массива GameObjectInfo)
 *          и сохраняет их в своем внутреннем кэше (std::map). Он больше не использует структуры-слепки
 *          из /shared/Structures, а работает напрямую с "контрактом" GameObjectInfo, что упрощает
 *          логику и позволяет легко получать доступ ко всем нужным данным, включая entryId.
 */
class GameObjectManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор.
     * @param parent Родительский QObject.
     */
    explicit GameObjectManager(QObject* parent = nullptr);
    ~GameObjectManager() override;

    /**
     * @brief Обновляет внутренний кэш объектов на основе свежих данных из общей памяти.
     * @param data Структура SharedData, прочитанная из Shared Memory.
     */
    void updateFromSharedMemory(const SharedData& data);

    /**
     * @brief Найти объект в кэше по его уникальному идентификатору (GUID).
     * @param guid GUID искомого объекта.
     * @return Константный указатель на GameObjectInfo, если объект найден, иначе nullptr.
     */
    const GameObjectInfo* getObjectByGuid(uint64_t guid) const;

    /**
     * @brief Получить все объекты заданного типа.
     * @param type Тип искомых объектов (Unit, GameObject, Player и т.д.).
     * @return Вектор константных указателей на GameObjectInfo.
     */
    std::vector<const GameObjectInfo*> getObjectsByType(GameObjectType type) const;

    /**
     * @brief Получить все объекты, которые есть в кэше.
     * @return Вектор константных указателей на все закэшированные GameObjectInfo.
     */
    std::vector<const GameObjectInfo*> getAllObjects() const;

    /**
     * @brief Проверяет, есть ли у объекта с заданным GUID определенная аура.
     * @param guid GUID проверяемого объекта.
     * @param spellId ID искомой ауры (баффа/дебаффа).
     * @return true, если у объекта есть такая аура, иначе false.
     */
    bool unitHasAura(uint64_t guid, int32_t spellId) const;

   private:
    /**
     * @brief Внутренний кэш игровых объектов.
     * @details Ключ - 64-битный GUID объекта.
     *          Значение - структура GameObjectInfo, содержащая всю необходимую для бота информацию
     *          (включая GUID, entryId, тип, позицию, здоровье и т.д.).
     */
    std::map<uint64_t, GameObjectInfo> m_gameObjects;
};