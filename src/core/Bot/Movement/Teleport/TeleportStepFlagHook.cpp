#include "TeleportStepFlagHook.h"
#include <QByteArray>

Q_LOGGING_CATEGORY(logTeleportHook, "core.bot.movement.teleport.hook")

TeleportStepFlagHook::TeleportStepFlagHook(uintptr_t address, uintptr_t playerStructAddrBuffer, uintptr_t flagBuffer,
                                           MemoryManager* memoryManager)
    : InlineHook(address, 0, memoryManager), m_playerStructAddrBuffer(playerStructAddrBuffer), m_flagBuffer(flagBuffer)
{
    qCInfo(logTeleportHook) << "TeleportStepFlagHook created for address" << Qt::hex << address;
}

bool TeleportStepFlagHook::generateTrampoline()
{
    if (!m_trampolinePtr || !m_memoryManager)
    {
        qCCritical(logTeleportHook) << "Cannot generate trampoline: trampolinePtr or memoryManager is not initialized.";
        return false;
    }

    QByteArray shellcode;

    // cmp ecx, [m_playerStructAddrBuffer]
    shellcode.append(static_cast<char>(0x39));
    shellcode.append(static_cast<char>(0x0D));
    shellcode.append(reinterpret_cast<const char*>(&m_playerStructAddrBuffer), sizeof(uintptr_t));

    // jne skip_writing_flag (прыжок на 7 байт, которые занимает инструкция mov)
    shellcode.append(static_cast<char>(0x75));
    shellcode.append(static_cast<char>(0x07));

    // mov byte ptr [m_flagBuffer], 1
    shellcode.append(static_cast<char>(0xC6));
    shellcode.append(static_cast<char>(0x05));
    shellcode.append(reinterpret_cast<const char*>(&m_flagBuffer), sizeof(uintptr_t));
    shellcode.append(static_cast<char>(0x01));

    // Копируем оригинальные байты, которые были затерты нашим JMP.
    shellcode.append(m_originalBytes);

    // --- Расчет JMP обратно в оригинальный код ---
    const uintptr_t returnAddr = m_address + m_patchSize;                              // Куда прыгать
    const uintptr_t jmpSrcAddr = m_trampolinePtr + shellcode.size();                   // Откуда прыгать
    const int32_t relativeAddr = static_cast<int32_t>(returnAddr - (jmpSrcAddr + 5));  // Вычисляем смещение

    shellcode.append(static_cast<char>(0xE9));
    shellcode.append(reinterpret_cast<const char*>(&relativeAddr), sizeof(int32_t));

    if (!m_memoryManager->writeMemory(m_trampolinePtr, shellcode.constData(), shellcode.size()))
    {
        qCCritical(logTeleportHook) << "Failed to write trampoline shellcode to" << Qt::hex << m_trampolinePtr;
        return false;
    }

    qCInfo(logTeleportHook) << "Teleport trampoline generated successfully at" << Qt::hex << m_trampolinePtr
                            << "size:" << shellcode.size();
    return true;
}

QString TeleportStepFlagHook::description() const
{
    return QString("TeleportStepFlagHook at 0x%1").arg(m_address, 0, 16);
}