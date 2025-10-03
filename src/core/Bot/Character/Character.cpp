#include "Character.h"
#include <QLoggingCategory>
#include <bit>  // ВАЖНО: Подключаем для std::popcount (стандарт C++20)

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

uint32_t Character::getCurrentPower(PowerType type) const
{
    if (!m_sharedData)
    {
        qCWarning(characterLog) << "Attempted to get current power with no shared data available.";
        return 0;
    }

    // Используем switch для выбора и возврата значения нужного ресурса
    // из общей памяти, где оно уже находится в "человеческом" виде.
    switch (type)
    {
        case PowerType::Mana:
            return m_sharedData->player.Mana;
        case PowerType::Rage:
            return m_sharedData->player.Rage;
        case PowerType::Energy:
            return m_sharedData->player.Energy;
        case PowerType::RunicPower:
            return m_sharedData->player.RunicPower;
        default:
            qCWarning(characterLog) << "getCurrentPower was called with an unknown PowerType!";
            return 0;
    }
}

uint32_t Character::getMaxPower(PowerType type) const
{
    if (!m_sharedData)
    {
        qCWarning(characterLog) << "Attempted to get max power with no shared data available.";
        return 0;
    }

    switch (type)
    {
        case PowerType::Mana:
            return m_sharedData->player.maxMana;
        case PowerType::Rage:
            return 100;  // Ярость всегда имеет максимум 100.
        case PowerType::Energy:
            return 100;  // Энергия по умолчанию 100 (таланты пока не учитываем).
        case PowerType::RunicPower:
            // Максимум Силы Рун может меняться с талантами, но базовое значение 100.
            return 100;
        default:
            qCWarning(characterLog) << "getMaxPower was called with an unknown PowerType!";
            return 0;
    }
}

/**
 * @brief Пространство имен для констант-масок, используемых при анализе состояния рун.
 * @details Инкапсуляция масок в отдельное пространство имен предотвращает загрязнение
 *          глобальной области и делает код более читаемым и поддерживаемым.
 */
namespace RuneMasks
{
/// @brief Маска для двух рун Крови (биты 0 и 1).
constexpr uint32_t BLOOD = 0b00000011;  // 3
/// @brief Маска для двух рун Нечестивости (биты 2 и 3).
constexpr uint32_t UNHOLY = 0b00001100;  // 12
/// @brief Маска для двух рун Льда (биты 4 и 5).
constexpr uint32_t FROST = 0b00110000;  // 48
}  // namespace RuneMasks

int Character::getRuneCount(RuneType type) const
{
    if (!m_sharedData)
    {
        return 0;
    }

    // Получаем актуальную маску из общей памяти.
    const uint32_t mask = m_sharedData->player.runeStatusMask;

    // Используем switch для выбора нужной маски и подсчета битов.
    switch (type)
    {
        case RuneType::Blood:
            // Применяем маску Крови и считаем установленные биты.
            // std::popcount - сверхбыстрая аппаратная инструкция для подсчета единичных битов.
            return std::popcount(mask & RuneMasks::BLOOD);

        case RuneType::Frost:
            // Применяем маску Льда и считаем установленные биты.
            return std::popcount(mask & RuneMasks::FROST);

        case RuneType::Unholy:
            // Применяем маску Нечестивости и считаем установленные биты.
            return std::popcount(mask & RuneMasks::UNHOLY);

        default:
            // На случай, если будет передан некорректный тип руны.
            qCWarning(characterLog) << "getRuneCount was called with an unknown RuneType.";
            return 0;
    }
}