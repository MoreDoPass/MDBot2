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

    /**
     * @brief Проверяет, находится ли юнит с заданным GUID в состоянии боя.
     * @details Эта функция является ключевой для боевой логики. Она обращается к данным
     *          объекта, полученным из DLL, и анализирует поле 'flags'.
     *
     *          Механизм проверки основан на реверс-инжиниринге функции LUA `UnitAffectingCombat`:
     *          - Состояние боя хранится в виде битового флага.
     *          - Этот флаг находится в 19-м бите 32-битного поля 'flags'.
     *          - Для проверки используется побитовая операция 'И' с маской 0x80000.
     *
     *          Благодаря этому методу, вся сложная логика инкапсулирована здесь,
     *          а Дерево Поведения использует простое и понятное условие.
     *
     * @param guid GUID юнита (игрока, NPC, цели), которого нужно проверить.
     * @return true, если у юнита установлен флаг боя, иначе false.
     */
    bool isUnitInCombat(uint64_t guid) const;

    /**
     * @brief Получает GUID цели для указанного юнита.
     * @details Этот метод обращается к данным, полученным из DLL, и возвращает
     *          GUID объекта, который в данный момент находится в цели у юнита.
     *          Если юнит никого не выбрал, возвращает 0.
     * @param guid GUID юнита (игрока, NPC), чью цель мы хотим узнать.
     * @return 64-битный GUID цели или 0, если цель отсутствует.
     */
    uint64_t getUnitTargetGuid(uint64_t guid) const;

    /**
     * @brief Проверяет, кастует ли указанный юнит какое-либо заклинание.
     * @param unitGuid GUID юнита для проверки.
     * @return true, если юнит находится в процессе каста.
     */
    bool isUnitCasting(uint64_t unitGuid) const;

    /**
     * @brief Получает ID заклинания, которое кастует указанный юнит.
     * @param unitGuid GUID юнита для проверки.
     * @return ID заклинания, если юнит кастует, иначе 0.
     */
    uint32_t getUnitCastingSpellId(uint64_t unitGuid) const;

   private:
    /**
     * @brief Внутренний кэш игровых объектов.
     * @details Ключ - 64-битный GUID объекта.
     *          Значение - структура GameObjectInfo, содержащая всю необходимую для бота информацию
     *          (включая GUID, entryId, тип, позицию, здоровье и т.д.).
     */
    std::map<uint64_t, GameObjectInfo> m_gameObjects;
};