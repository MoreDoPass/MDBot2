#pragma once
#include "shared/Data/SharedData.h"  // Нужен, чтобы знать о структуре ClientCommand

/**
 * @class InteractionManager
 * @brief Отвечает за выполнение команд взаимодействия с игровым миром (правый клик).
 */
class InteractionManager
{
   public:
    /**
     * @brief Обрабатывает команды, относящиеся к взаимодействию.
     * @param cmd Ссылка на команду, полученную из общей памяти.
     */
    void ExecuteCommand(const ClientCommand& cmd);
};