#include "CharacterHook.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(characterHookLog, "mdbot.characterhook")

CharacterHook::CharacterHook(uintptr_t address, MemoryManager* memoryManager, uintptr_t savePtrAddress)
    : InlineHook(address, 0, memoryManager), m_savePtrAddress(savePtrAddress)
{
    qCInfo(characterHookLog) << "CharacterHook created for address" << Qt::hex << address << "to save EAX at" << Qt::hex
                             << savePtrAddress;
}

bool CharacterHook::generateTrampoline()
{
    if (!m_trampolinePtr || !m_savePtrAddress || !m_memoryManager)
    {
        qCCritical(characterHookLog) << "Cannot generate trampoline: one of the required pointers is null!";
        return false;
    }

    QByteArray shellcode;

    // mov [savePtrAddress], eax : A3 <imm32>
    shellcode.append(static_cast<char>(0xA3));
    shellcode.append(reinterpret_cast<const char*>(&m_savePtrAddress), sizeof(uintptr_t));

    // Копируем оригинальные байты, которые были затерты нашим JMP.
    // m_originalBytes и m_patchSize уже подготовлены базовым классом InlineHook.
    shellcode.append(m_originalBytes);

    // --- Расчет JMP обратно в оригинальный код ---
    const uintptr_t returnAddr = m_address + m_patchSize;                              // Куда прыгать
    const uintptr_t jmpSrcAddr = m_trampolinePtr + shellcode.size();                   // Откуда прыгать
    const int32_t relativeAddr = static_cast<int32_t>(returnAddr - (jmpSrcAddr + 5));  // Вычисляем смещение

    // Добавляем инструкцию jmp в shellcode
    shellcode.append(static_cast<char>(0xE9));
    shellcode.append(reinterpret_cast<const char*>(&relativeAddr), sizeof(int32_t));

    // Записываем весь сгенерированный shellcode в память процесса
    if (!m_memoryManager->writeMemory(m_trampolinePtr, shellcode.constData(), shellcode.size()))
    {
        qCCritical(characterHookLog) << "Failed to write trampoline to process memory!";
        return false;
    }

    qCInfo(characterHookLog) << "CharacterHook trampoline generated successfully";
    return true;
}