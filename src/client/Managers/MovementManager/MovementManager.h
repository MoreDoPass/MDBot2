#pragma once
#include "shared/Data/SharedData.h"  // Нужен для ClientCommand
#include <cstdint>                   // Нужен для uintptr_t

/**
 * @class MovementManager
 * @brief Отвечает за выполнение всех команд, связанных с движением персонажа.
 */
class MovementManager
{
   public:
    /**
     * @brief Обрабатывает команды, относящиеся к движению.
     * @param cmd Ссылка на команду, полученную из общей памяти.
     * @param playerPtr Указатель на объект нашего персонажа.
     */
    void ExecuteCommand(const ClientCommand& cmd, uintptr_t playerPtr);
};