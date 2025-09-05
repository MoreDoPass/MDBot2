#include "Character.h"
#include <QLoggingCategory>
#include <cstring>  // для memcmp

Q_LOGGING_CATEGORY(characterLog, "mdbot.character")

/**
 * @brief Конструктор.
 * @details Логика по установке хуков и выделению памяти полностью удалена.
 *          Класс создается в "чистом" виде.
 */
Character::Character(QObject* parent) : QObject(parent)
{
    // Инициализируем m_data нулями, чтобы избежать мусора при первом сравнении.
    memset(&m_data, 0, sizeof(CharacterData));
    qCInfo(characterLog) << "Character object created (Shared Memory mode).";
}

/**
 * @brief Деструктор.
 * @details Логика по снятию хуков и освобождению памяти полностью удалена.
 */
Character::~Character()
{
    qCInfo(characterLog) << "Character object destroyed.";
}

/**
 * @brief Обновляет внутреннее состояние персонажа на основе данных, полученных от DLL.
 * @details Перед обновлением и отправкой сигнала, метод сравнивает новые данные
 *          со старыми, чтобы избежать лишней работы и спама сигналами/логами.
 * @param newData Структура PlayerData, прочитанная из общей памяти.
 */
void Character::updateFromSharedMemory(const PlayerData& newData)
{
    // Сравниваем старые и новые данные, чтобы не испускать сигнал без надобности.
    // memcmp - очень быстрая операция для сравнения блоков памяти.
    if (memcmp(&m_data, &newData, sizeof(CharacterData)) != 0)
    {
        m_data = newData;  // Копируем новые данные
        emit dataChanged(m_data);

        // Логируем только при изменении, чтобы не спамить в консоль.
        qCDebug(characterLog) << "Player data updated: HP:" << m_data.health << "/" << m_data.maxHealth
                              << "Pos:" << m_data.position.x << m_data.position.y << m_data.position.z
                              << "GUID:" << Qt::hex << m_data.guid;
    }
}

/**
 * @brief Получить текущую позицию персонажа.
 * @return Vector3 - Координаты (X, Y, Z).
 */
Vector3 Character::GetPosition() const
{
    return m_data.position;
}

/**
 * @brief Получить базовый адрес структуры персонажа в памяти игры.
 * @return Адрес в памяти или 0.
 */
uintptr_t Character::getBaseAddress() const
{
    return m_data.baseAddress;
}

/**
 * @brief Получить GUID персонажа.
 * @return 64-битный GUID.
 */
uint64_t Character::getGuid() const
{
    return m_data.guid;
}

/**
 * @brief Получить уровень персонажа.
 * @return Уровень.
 */
uint32_t Character::getLevel() const
{
    return m_data.level;
}

/**
 * @brief Получить текущее здоровье персонажа.
 * @return Текущее здоровье.
 */
uint32_t Character::getHealth() const
{
    return m_data.health;
}

/**
 * @brief Получить максимальное здоровье персонажа.
 * @return Максимальное здоровье.
 */
uint32_t Character::getMaxHealth() const
{
    return m_data.maxHealth;
}

/**
 * @brief Получить текущую ману/энергию/ярость персонажа.
 * @return Текущая мана.
 */
uint32_t Character::getMana() const
{
    return m_data.mana;
}

/**
 * @brief Получить максимальную ману/энергию/ярость персонажа.
 * @return Максимальная мана.
 */
uint32_t Character::getMaxMana() const
{
    return m_data.maxMana;
}

/**
 * @brief Получить все данные персонажа одной структурой.
 * @return Константная ссылка на внутреннюю структуру данных.
 */
const CharacterData& Character::data() const
{
    return m_data;
}