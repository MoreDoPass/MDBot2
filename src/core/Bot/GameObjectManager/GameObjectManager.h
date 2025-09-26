#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <vector>
#include "Shared/Data/SharedData.h"

Q_DECLARE_LOGGING_CATEGORY(logGOM)

class GameObjectManager : public QObject
{
    Q_OBJECT
   public:
    // 1. Конструктор теперь принимает указатель на SharedData.
    explicit GameObjectManager(const SharedData* sharedData, QObject* parent = nullptr);
    ~GameObjectManager() override;

    // 2. Метод updateFromSharedMemory ПОЛНОСТЬЮ УДАЛЕН.

    // --- Методы для "живого" доступа к данным ---
    // (Их объявления не меняются, меняется только их реализация)
    const GameObjectInfo* getObjectByGuid(uint64_t guid) const;
    std::vector<const GameObjectInfo*> getObjectsByType(GameObjectType type) const;
    std::vector<const GameObjectInfo*> getAllObjects() const;

    bool unitHasAura(uint64_t guid, int32_t spellId) const;
    bool isUnitInCombat(uint64_t guid) const;
    uint64_t getUnitTargetGuid(uint64_t guid) const;
    bool isUnitCasting(uint64_t unitGuid) const;
    uint32_t getUnitCastingSpellId(uint64_t unitGuid) const;

    /**
     * @brief Проверяет, активна ли автоатака у указанного юнита.
     * @param guid 64-битный GUID юнита для проверки.
     * @return true, если юнит атакует, иначе false.
     */
    bool isAutoAttacking(uint64_t guid) const;

   private:
    // 3. Внутренний кэш m_gameObjects ПОЛНОСТЬЮ УДАЛЕН.

    // 4. Вместо него - один указатель на "Источник Правды".
    const SharedData* m_sharedData;
};