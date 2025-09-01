#include "VisibleObjectsHook.h"

// Адрес, который ты нашел: mov eax, [esi]
// Это идеальное место, чтобы прочитать указатель на объект из ESI.
VisibleObjectsHook::VisibleObjectsHook() : InlineHook(0x743461)
{
    InitializeCriticalSection(&m_lock);
}

VisibleObjectsHook::~VisibleObjectsHook()
{
    DeleteCriticalSection(&m_lock);
}

void VisibleObjectsHook::handler(const Registers* regs)
{
    // Этот handler должен быть МАКСИМАЛЬНО быстрым.
    // Просто захватываем блокировку, добавляем указатель из ESI и выходим.
    // Никаких чтений памяти, никакой сложной логики.
    if (regs)
    {
        EnterCriticalSection(&m_lock);
        m_visibleObjects.insert(regs->esi);
        LeaveCriticalSection(&m_lock);
    }
    // Трамплин вызовется автоматически после выхода из этой функции.
}

std::set<uintptr_t> VisibleObjectsHook::getAndClearObjects()
{
    std::set<uintptr_t> objectsCopy;
    EnterCriticalSection(&m_lock);
    // std::move более эффективен, чем копирование, он "перемещает" содержимое
    // одного сета в другой, оставляя исходный пустым.
    objectsCopy = std::move(m_visibleObjects);
    LeaveCriticalSection(&m_lock);
    return objectsCopy;
}