#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <QString>
#include "shared/Data/SharedData.h"  // <-- Подключаем "контракт" для PlayerData
#include "shared/Utils/Vector.h"

/**
 * @brief Категория логирования для класса Character.
 */
Q_DECLARE_LOGGING_CATEGORY(characterLog)

/**
 * @brief Для ясности кода, определяем, что "данные персонажа" в этом классе
 *        - это структура PlayerData из общей библиотеки.
 */
using CharacterData = PlayerData;

/**
 * @brief Класс для работы с данными персонажа в MDBot2.
 * @details Теперь это простой класс-хранилище. Он не читает память игры напрямую,
 *          а получает все данные извне (от класса Bot) через метод updateFromSharedMemory.
 *          Он является QObject'ом для отправки сигналов об изменении данных в GUI.
 */
class Character : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Упрощенный конструктор.
     * @param parent Родительский QObject.
     */
    explicit Character(QObject* parent = nullptr);

    /**
     * @brief Деструктор.
     */
    ~Character();

    /**
     * @brief Обновляет внутренние данные на основе свежих данных из общей памяти.
     * @param data Структура PlayerData, прочитанная из Shared Memory.
     */
    void updateFromSharedMemory(const PlayerData& data);

    // --- Геттеры для доступа к данным ---

    /**
     * @brief Получить текущую позицию персонажа.
     * @return Vector3 - Координаты (X, Y, Z).
     */
    Vector3 GetPosition() const;

    /**
     * @brief Получить базовый адрес структуры персонажа в памяти игры.
     * @details Этот адрес нужен, например, для работы системы телепортации.
     * @return Адрес в памяти или 0, если он еще не получен от DLL.
     */
    uintptr_t getBaseAddress() const;

    /**
     * @brief Получить GUID персонажа.
     * @return 64-битный GUID.
     */
    uint64_t getGuid() const;

    /**
     * @brief Получить уровень персонажа.
     * @return Уровень.
     */
    uint32_t getLevel() const;

    /**
     * @brief Получить текущее здоровье персонажа.
     * @return Текущее здоровье.
     */
    uint32_t getHealth() const;

    /**
     * @brief Получить максимальное здоровье персонажа.
     * @return Максимальное здоровье.
     */
    uint32_t getMaxHealth() const;

    /**
     * @brief Получить текущую ману/энергию/ярость персонажа.
     * @return Текущая мана.
     */
    uint32_t getMana() const;

    /**
     * @brief Получить максимальную ману/энергию/ярость персонажа.
     * @return Максимальная мана.
     */
    uint32_t getMaxMana() const;

    /**
     * @brief Получить все данные персонажа одной структурой.
     * @return Константная ссылка на внутреннюю структуру данных.
     */
    const CharacterData& data() const;

    // --- НОВЫЕ МЕТОДЫ-ГЕТТЕРЫ ДЛЯ КУЛДАУНОВ ---
    /**
     * @brief Проверяет, активен ли в данный момент боевой ГКД.
     * @return true, если ГКД активен.
     */
    bool isGcdActive() const;

    /**
     * @brief Проверяет, находится ли указанное заклинание на кулдауне.
     * @param spellId ID заклинания для проверки.
     * @return true, если заклинание на кулдауне.
     */
    bool isSpellOnCooldown(uint32_t spellId) const;

   signals:
    /**
     * @brief Сигнал испускается, когда данные персонажа изменяются.
     * @param data Новые данные персонажа.
     */
    void dataChanged(const CharacterData& data);

   private:
    /// @brief Внутренний кэш данных персонажа. Является копией PlayerData из Shared Memory.
    CharacterData m_data;

    // Кэш состояния боевого ГКД.
    bool m_isGcdActive = false;

    // Кэш ID активных кулдаунов заклинаний для быстрого поиска.
    QSet<uint32_t> m_activeCooldownIds;
};