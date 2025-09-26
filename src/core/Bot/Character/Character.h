#pragma once

#include <QObject>
#include <QLoggingCategory>
#include "shared/Data/SharedData.h"
#include "shared/Utils/Vector.h"

Q_DECLARE_LOGGING_CATEGORY(characterLog)

class Character : public QObject
{
    Q_OBJECT
   public:
    // 1. Конструктор теперь принимает указатель на SharedData.
    explicit Character(const SharedData* sharedData, QObject* parent = nullptr);
    ~Character();

    // 2. Метод updateFromSharedMemory ПОЛНОСТЬЮ УДАЛЕН. Он больше не нужен.

    // --- Геттеры для "живого" доступа к данным ---
    // (Их объявления не меняются, меняется только их реализация)
    Vector3 getPosition() const;

    /**
     * @brief Получает горизонтальный угол поворота персонажа в радианах.
     * @return Угол поворота.
     */
    float getOrientation() const;
    uintptr_t getBaseAddress() const;
    uint64_t getGuid() const;
    uint32_t getLevel() const;
    uint32_t getHealth() const;
    uint32_t getMaxHealth() const;
    uint32_t getMana() const;
    uint32_t getMaxMana() const;

    /**
     * @brief Получает список ID всех активных аур на персонаже.
     * @return QVector со списком ID.
     */
    QVector<int32_t> getAuras() const;

    /**
     * @brief Получает список ID всех заклинаний, находящихся на кулдауне.
     * @return QVector со списком ID.
     */
    QVector<uint32_t> getCooldowns() const;

    bool isGcdActive() const;
    bool isSpellOnCooldown(uint32_t spellId) const;
    bool hasAura(int32_t spellId) const;  // <-- Добавим новый полезный геттер для аур

    /**
     * @brief Проверяет, произносит ли персонаж какое-либо заклинание.
     * @return true, если персонаж кастует.
     */
    bool isCasting() const;

    /**
     * @brief Проверяет, находится ли персонаж в состоянии боя.
     * @return true, если установлен флаг боя.
     */
    bool isInCombat() const;

    /**
     * @brief Проверяет, активна ли в данный момент автоатака у персонажа.
     * @return true, если персонаж атакует, иначе false.
     */
    bool isAutoAttacking() const;

    /**
     * @brief Получает ID заклинания, которое персонаж кастует в данный момент.
     * @return ID заклинания или 0, если каста нет.
     */
    uint32_t getCastingSpellId() const;

    /**
     * @brief Получает GUID текущей цели персонажа.
     * @return 64-битный GUID цели или 0, если цель отсутствует.
     */
    uint64_t getTargetGuid() const;

   signals:
    // 3. Сигнал больше не несет данные, он просто уведомляет об обновлении.
    void dataRefreshed();

   private:
    // 4. Все старые поля-копии УДАЛЕНЫ.
    // Вместо них - один указатель на "Источник Правды".
    const SharedData* m_sharedData;
};