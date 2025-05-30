#pragma once
#include "core/HookManager/Hook/InlineHook/InlineHook.h"
#include <QLoggingCategory>
#include <windows.h>
#include "core/MemoryManager/MemoryManager.h"

Q_DECLARE_LOGGING_CATEGORY(logCtMEnabler)

/**
 * @brief Хук для включения ClickToMove в WoW 3.3.5a (Sirus)
 *
 * Ставит InlineHook на 0x00721F7A, перехватывает ECX, по адресу (ECX+0x30) пишет 1 (DWORD), после чего хук можно
 * удалить.
 */
class CtMEnablerHook : public InlineHook
{
   public:
    explicit CtMEnablerHook(MemoryManager* memory);

    /**
     * @brief Генерирует трамплин (jmp обратно)
     */
    bool generateTrampoline() override;

    QString description() const override;

   private:
    MemoryManager* m_memory;
};
