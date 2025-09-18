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

   private:
    // Указатель на общую память, через которую мы будем общаться с DLL
    SharedMemoryManager* m_sharedMemory;
};