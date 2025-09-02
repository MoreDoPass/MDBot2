#pragma once

#include "Core/Hooking/InlineHook.h"

/**
 * @class CtMEnablerHook
 * @brief Хук для включения функции Click-To-Move (CtM).
 * @details Устанавливается на функцию, которая вызывается при входе в мир или смене локации.
 * Перехватывает момент инициализации указателя на объект игрока, читает этот указатель
 * и использует его для записи флага, активирующего CtM. Хук остается активным,
 * чтобы повторно включать CtM при необходимости (например, после телепортации).
 */
class CtMEnablerHook : public InlineHook
{
   public:
    /**
     * @brief Конструктор.
     */
    CtMEnablerHook();

   protected:
    /**
     * @brief Обработчик хука. Выполняет основную логику по включению CtM.
     * @param regs Указатель на сохраненные регистры процессора.
     */
    void handler(const Registers* regs) override;
};