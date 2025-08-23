#ifndef INLINEHOOK_H
#define INLINEHOOK_H

#include "core/hooks/ihook.h"
#include "core/memory/memorymanager.h"  // Добавляем include для MemoryManager
#include <cstdint>
#include <QtDebug>

// Callback: вызывается при срабатывании хука, можно обработать регистры
using InlineHookCallback = void (*)(uint32_t* pEax /*, другие регистры по желанию*/);

class InlineHook : public IHook
{
   public:
    // addr - адрес функции, которую перехватываем
    // callback - функция, вызываемая при срабатывании хука
    // patchSize - сколько байт заменяем (обычно 5)
    // Добавляем MemoryManager& как параметр конструктора
    InlineHook(void* addr, InlineHookCallback callback, MemoryManager& mem, int patchSize = 5);
    ~InlineHook();

    bool install() override;
    bool remove() override;
    bool isInstalled() const override;
    size_t getPatchSize() const
    {
        return patchSize;
    }

   protected:
    // Делаем createTrampoline защищённым, чтобы наследники могли переопределять
    virtual bool createTrampoline();
    void writeJump(void* from, void* to);
    MemoryManager& memoryManager;
    void* targetAddr;  // Адрес функции
    InlineHookCallback callback;
    int patchSize;
    bool installed;
    uint8_t originalBytes[16];  // Оригинальные байты (до 16)
    void* trampoline;           // Указатель на трамплин
};

#endif  // INLINEHOOK_H
