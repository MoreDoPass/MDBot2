#include "Character.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(characterLog, "mdbot.character")

Character::Character(const SharedData* sharedData, QObject* parent) : QObject(parent), m_sharedData(sharedData)
{
    qCInfo(characterLog) << "Character object created (Direct Memory Access mode).";
}

Character::~Character()
{
    qCInfo(characterLog) << "Character object destroyed.";
}

Vector3 Character::getPosition() const
{
    // Паттерн "проверь указатель - верни данные"
    if (m_sharedData)
    {
        return m_sharedData->player.position;
    }
    return {};  // Возвращаем пустой вектор, если данных нет
}

float Character::getOrientation() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.orientation;
    }
    return 0.0f;
}

uintptr_t Character::getBaseAddress() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.baseAddress;
    }
    return 0;
}

uint64_t Character::getGuid() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.guid;
    }
    return 0;
}

uint32_t Character::getLevel() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.level;
    }
    return 0;
}

uint32_t Character::getHealth() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.Health;
    }
    return 0;
}

uint32_t Character::getMaxHealth() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.maxHealth;
    }
    return 0;
}

uint32_t Character::getMana() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.Mana;
    }
    return 0;
}

uint32_t Character::getMaxMana() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.maxMana;
    }
    return 0;
}

uint64_t Character::getTargetGuid() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.targetGuid;
    }
    return 0;
}

bool Character::isGcdActive() const
{
    if (m_sharedData)
    {
        return m_sharedData->player.isGcdActive;
    }
    return false;
}

bool Character::isSpellOnCooldown(uint32_t spellId) const
{
    if (m_sharedData)
    {
        // Пробегаемся по "живому" массиву кулдаунов в общей памяти.
        // Это очень быстро для такого маленького массива.
        for (int i = 0; i < m_sharedData->player.activeCooldownCount; ++i)
        {
            if (m_sharedData->player.activeCooldowns[i].spellId == spellId)
            {
                return true;  // Нашли!
            }
        }
    }
    return false;  // Не нашли или данных нет
}

bool Character::hasAura(int32_t spellId) const
{
    if (m_sharedData)
    {
        // Точно так же пробегаемся по "живому" массиву аур.
        for (int i = 0; i < m_sharedData->player.auraCount; ++i)
        {
            if (m_sharedData->player.auras[i] == spellId)
            {
                return true;  // Нашли!
            }
        }
    }
    return false;
}

QVector<int32_t> Character::getAuras() const
{
    QVector<int32_t> result;
    if (m_sharedData)
    {
        // Резервируем память для эффективности
        result.reserve(m_sharedData->player.auraCount);
        // Просто копируем все ID из "живого" массива в наш результат
        for (int i = 0; i < m_sharedData->player.auraCount; ++i)
        {
            result.append(m_sharedData->player.auras[i]);
        }
    }
    return result;
}

QVector<uint32_t> Character::getCooldowns() const
{
    QVector<uint32_t> result;
    if (m_sharedData)
    {
        result.reserve(m_sharedData->player.activeCooldownCount);
        // Копируем все ID из "живого" массива кулдаунов
        for (int i = 0; i < m_sharedData->player.activeCooldownCount; ++i)
        {
            result.append(m_sharedData->player.activeCooldowns[i].spellId);
        }
    }
    return result;
}

bool Character::isCasting() const
{
    if (m_sharedData)
    {
        // Просто возвращаем флаг, который нам прислала DLL
        return m_sharedData->player.isCasting;
    }
    return false;  // Если данных нет, считаем, что каста нет
}

uint32_t Character::getCastingSpellId() const
{
    if (m_sharedData)
    {
        // Возвращаем ID заклинания
        return m_sharedData->player.castingSpellId;
    }
    return 0;  // Если данных нет, возвращаем 0
}

bool Character::isInCombat() const
{
    if (m_sharedData)
    {
        // Используем ту же логику, что и в GameObjectManager:
        // проверяем 19-й бит (маска 0x80000).
        return (m_sharedData->player.flags & 0x80000) != 0;
    }
    return false;
}

bool Character::isAutoAttacking() const
{
    if (m_sharedData)
    {
        // Просто проверяем, не равен ли GUID цели автоатаки нулю.
        return m_sharedData->player.autoAttackTargetGuid != 0;
    }
    return false;
}