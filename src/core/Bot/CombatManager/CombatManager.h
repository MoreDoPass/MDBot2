// Файл: src/core/bot/CombatManager/CombatManager.h
#pragma once

#include <QObject>
#include <cstdint>
#include "core/SharedMemoryManager/SharedMemoryManager.h"

class CombatManager : public QObject
{
   Q_OBJECT  // Обязательно для классов Qt
       public :
       // Конструктор, который принимает указатель на общую память
       explicit CombatManager(SharedMemoryManager* sharedMemory, QObject* parent = nullptr);

    // НАШ ГЛАВНЫЙ МЕТОД: "Кастануть заклинание в цель"
    // Он будет принимать ID спелла и GUID цели.
    // Возвращает true, если команда успешно отправлена.
    bool castSpellOnTarget(int spellId, uint64_t targetGUID);

    /**
     * @brief Отправляет в DLL команду на начало автоатаки по указанной цели.
     * @details Является "действием" для дерева поведения.
     * @param targetGUID 64-битный GUID цели, которую нужно атаковать.
     * @return true, если команда была успешно отправлена, false - если DLL занята.
     */
    bool startAutoAttack(uint64_t targetGUID);

   private:
    // Указатель на общую память, через которую мы будем общаться с DLL
    SharedMemoryManager* m_sharedMemory;
};