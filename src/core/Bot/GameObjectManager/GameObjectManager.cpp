#include "GameObjectManager.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logGOM, "mdbot.gom")

GameObjectManager::GameObjectManager(const SharedData* sharedData, QObject* parent)
    : QObject(parent), m_sharedData(sharedData)
{
    qCInfo(logGOM) << "GameObjectManager created (Direct Memory Access mode).";
}

GameObjectManager::~GameObjectManager()
{
    qCInfo(logGOM) << "GameObjectManager destroyed.";
}

const GameObjectInfo* GameObjectManager::getObjectByGuid(uint64_t guid) const
{
    if (!m_sharedData) return nullptr;

    // Пробегаемся по "живому" массиву в Shared Memory.
    for (int i = 0; i < m_sharedData->visibleObjectCount; ++i)
    {
        // Сравниваем GUID.
        if (m_sharedData->visibleObjects[i].guid == guid)
        {
            // Нашли! Возвращаем указатель прямо на элемент в общей памяти.
            return &m_sharedData->visibleObjects[i];
        }
    }

    return nullptr;  // Не нашли.
}

std::vector<const GameObjectInfo*> GameObjectManager::getObjectsByType(GameObjectType type) const
{
    std::vector<const GameObjectInfo*> result;
    if (!m_sharedData) return result;

    for (int i = 0; i < m_sharedData->visibleObjectCount; ++i)
    {
        if (m_sharedData->visibleObjects[i].type == type)
        {
            result.push_back(&m_sharedData->visibleObjects[i]);
        }
    }
    return result;
}

std::vector<const GameObjectInfo*> GameObjectManager::getAllObjects() const
{
    std::vector<const GameObjectInfo*> result;
    if (!m_sharedData) return result;

    result.reserve(m_sharedData->visibleObjectCount);
    for (int i = 0; i < m_sharedData->visibleObjectCount; ++i)
    {
        result.push_back(&m_sharedData->visibleObjects[i]);
    }
    return result;
}

bool GameObjectManager::unitHasAura(uint64_t guid, int32_t spellId) const
{
    const GameObjectInfo* info = getObjectByGuid(guid);  // Используем наш новый "живой" геттер
    if (!info) return false;

    // Пробегаемся по "живым" аурам найденного объекта.
    for (int i = 0; i < info->auraCount; ++i)
    {
        if (info->auras[i] == spellId)
        {
            return true;
        }
    }
    return false;
}

bool GameObjectManager::isUnitInCombat(uint64_t guid) const
{
    const GameObjectInfo* info = getObjectByGuid(guid);
    if (info)
    {
        return (info->flags & 0x80000) != 0;
    }
    return false;
}

uint64_t GameObjectManager::getUnitTargetGuid(uint64_t guid) const
{
    const GameObjectInfo* info = getObjectByGuid(guid);
    if (info)
    {
        return info->targetGuid;
    }
    return 0;
}

bool GameObjectManager::isUnitCasting(uint64_t unitGuid) const
{
    const GameObjectInfo* unit = getObjectByGuid(unitGuid);
    if (unit)
    {
        return unit->isCasting;
    }
    return false;
}

uint32_t GameObjectManager::getUnitCastingSpellId(uint64_t unitGuid) const
{
    const GameObjectInfo* unit = getObjectByGuid(unitGuid);
    if (unit)
    {
        return unit->castingSpellId;
    }
    return 0;
}

bool GameObjectManager::isAutoAttacking(uint64_t guid) const
{
    const GameObjectInfo* info = getObjectByGuid(guid);
    if (info)
    {
        // Проверяем поле в структуре GameObjectInfo
        return info->autoAttackTargetGuid != 0;
    }
    return false;
}