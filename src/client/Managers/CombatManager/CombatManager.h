#pragma once
#include "shared/Data/SharedData.h"  // Нужен для ClientCommand
#include <cstdint>                   // Нужен для uintptr_t

/**
 * @class CombatManager
 * @brief Отвечает за выполнение всех боевых команд (атака, заклинания).
 */
class CombatManager
{
   public:
    /**
     * @brief Обрабатывает команды, относящиеся к бою.
     * @param cmd Ссылка на команду, полученную из общей памяти.
     * @param playerPtr Указатель на объект нашего персонажа, так как он нужен для атаки.
     */
    void ExecuteCommand(const ClientCommand& cmd, uintptr_t playerPtr);
};