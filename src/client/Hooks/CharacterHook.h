#pragma once
#include "Core/Hooking/InlineHook.h"

/**
 * @class CharacterHook
 * @brief Хук для перехвата и сохранения указателя на структуру игрока.
 * @details Устанавливается на функцию, которая загружает указатель на
 *          структуру персонажа в регистр EAX. Хук перехватывает этот
 *          указатель и сохраняет его в глобальную переменную для
 *          дальнейшего использования другими системами внутри DLL.
 */
class CharacterHook : public InlineHook
{
   public:
    /**
     * @brief Конструктор.
     */
    CharacterHook();

   protected:
    /**
     * @brief Обработчик хука.
     * @param regs Указатель на сохраненные регистры.
     */
    void handler(const Registers* regs) override;
};