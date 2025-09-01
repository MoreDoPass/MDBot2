#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>
#include "core/MemoryManager/MemoryManager.h"
#include "Shared/Data/SharedData.h"
#include "shared/Structures/Player.h"
#include "shared/Structures/GameObject.h"

Q_DECLARE_LOGGING_CATEGORY(logGOM)

class GameObjectManager : public QObject
{
    Q_OBJECT
   public:
    explicit GameObjectManager(MemoryManager* memoryManager, QObject* parent = nullptr);
    ~GameObjectManager() override;

    void updateFromSharedMemory(const SharedData& data);

    WorldObject* getObjectByGuid(uint64_t guid) const;
    std::vector<WorldObject*> getObjectsByType(GameObjectType type) const;
    WorldObject* getTargetObject() const;

   private:
    MemoryManager* m_memoryManager;
    // В кэше мы храним указатели на базовый класс WorldObject,
    // чтобы иметь возможность хранить в одной карте и Unit, и GameObject.
    std::map<uint64_t, std::unique_ptr<WorldObject>> m_gameObjects;
};