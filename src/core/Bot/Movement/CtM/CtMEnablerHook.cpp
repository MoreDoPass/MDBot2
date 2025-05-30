#include "CtMEnablerHook.h"
#include "core/HookManager/Hook/InlineHook/InlineHook.h"
#include <QLoggingCategory>
#include <windows.h>
#include <cstdint>

Q_LOGGING_CATEGORY(logCtMEnabler, "mdbot.ctm.enabler")

constexpr uintptr_t CTM_ENABLE_HOOK_ADDR = 0x00721F7A;
constexpr int ECX_OFFSET = 0x30;

CtMEnablerHook::CtMEnablerHook(MemoryManager* memory) : InlineHook(CTM_ENABLE_HOOK_ADDR, 0, memory), m_memory(memory) {}

bool CtMEnablerHook::generateTrampoline()
{
    QByteArray code;
    // mov dword ptr [ecx+0x30], 1
    code.append(char(0xC7));        // opcode mov dword ptr [reg+disp], imm32
    code.append(char(0x41));        // ModRM: 01 000 001 (mod=01, reg=000, rm=001) => [ecx+disp8]
    code.append(char(ECX_OFFSET));  // disp8 = 0x30
    DWORD value = 1;
    code.append(reinterpret_cast<const char*>(&value), 4);  // imm32 = 1
    // Копируем оригинальные байты
    code.append(m_originalBytes);
    // jmp обратно
    uintptr_t returnAddr = m_address + m_patchSize;
    code.append(char(0xE9));
    int32_t relJmp = static_cast<int32_t>(returnAddr - (m_trampolinePtr + code.size() + 4));
    code.append(reinterpret_cast<const char*>(&relJmp), 4);
    return m_memoryManager->writeMemory(m_trampolinePtr, code.data(), code.size());
}

QString CtMEnablerHook::description() const
{
    return QString("CtMEnablerHook (InlineHook) at 0x%1").arg(m_address, 0, 16);
}
