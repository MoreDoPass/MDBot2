#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <QString>
#include "MemoryManager/MemoryManager.h"
#include "CharacterHook.h"

/**
 * @brief Категория логирования для Character.
 */
Q_DECLARE_LOGGING_CATEGORY(characterLog)

/**
 * @brief Смещения полей в структуре персонажа в памяти WoW.
 */
struct CharacterOffsets
{
    size_t level = 0x1A30;      ///< Смещение уровня
    size_t health = 0x19B8;     ///< Смещение текущего HP
    size_t maxHealth = 0x19D8;  ///< Смещение максимального HP
    size_t mana = 0x19BC;       ///< Смещение текущей маны
    size_t maxMana = 0x19DC;    ///< Смещение максимальной маны
    size_t posX = 0x798;        ///< Смещение X координаты
    size_t posY = 0x79C;        ///< Смещение Y координаты
    size_t posZ = 0x7A0;        ///< Смещение Z координаты
    // Добавь другие смещения по необходимости
};

/**
 * @brief Структура для хранения актуальных данных персонажа.
 */
struct CharacterData
{
    uint8_t level = 0;
    uint32_t health = 0;
    uint32_t maxHealth = 0;
    uint32_t mana = 0;
    uint32_t maxMana = 0;
    float posX = 0.0f;
    float posY = 0.0f;
    float posZ = 0.0f;
    QString name;
    bool inCombat = false;
    // Добавь другие поля по необходимости
};

/**
 * @brief Класс для работы с данными персонажа в памяти WoW.
 */
class Character : public QObject
{
    Q_OBJECT
   public:
    explicit Character(MemoryManager* memoryManager, QObject* parent = nullptr);
    ~Character();

    void setBaseAddress(uintptr_t address);
    bool updateFromMemory();

    // Геттеры для доступа к данным
    uint32_t getLevel() const
    {
        return m_data.level;
    }
    uint32_t getHealth() const
    {
        return m_data.health;
    }
    uint32_t getMaxHealth() const
    {
        return m_data.maxHealth;
    }
    uint32_t getMana() const
    {
        return m_data.mana;
    }
    uint32_t getMaxMana() const
    {
        return m_data.maxMana;
    }
    float getPosX() const
    {
        return m_data.posX;
    }
    float getPosY() const
    {
        return m_data.posY;
    }
    float getPosZ() const
    {
        return m_data.posZ;
    }
    bool isInCombat() const
    {
        return m_data.inCombat;
    }
    QString getName() const
    {
        return m_data.name;
    }

    const CharacterData& data() const
    {
        return m_data;
    }

   signals:
    void dataChanged(const CharacterData& data);

   private:
    MemoryManager* m_memoryManager;
    uintptr_t m_baseAddress = 0;
    CharacterOffsets m_offsets;
    CharacterData m_data;
    CharacterHook* m_hook = nullptr;   ///< Хук для получения указателя на структуру персонажа
    void* m_savePtrAddress = nullptr;  ///< Адрес в run.exe для хранения указателя (void*, а не uintptr_t)
};