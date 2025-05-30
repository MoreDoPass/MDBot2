#include "CharacterHook.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(characterHookLog, "mdbot.characterhook")

CharacterHook::CharacterHook(uintptr_t address, MemoryManager* memoryManager, uintptr_t savePtrAddress)
    : InlineHook(address, 0, memoryManager), m_savePtrAddress(savePtrAddress)
{
    qCInfo(characterHookLog) << "CharacterHook создан для адреса" << Qt::hex << address << "с сохранением EAX по адресу"
                             << Qt::hex << savePtrAddress;
}

bool CharacterHook::generateTrampoline()
{
    if (!m_trampolinePtr || !m_savePtrAddress)
    {
        qCCritical(characterHookLog) << "Не инициализирована память для трамплина или savePtrAddress!";
        return false;
    }

    // Примерный байткод для x86:
    // mov [savePtrAddress], eax
    // ...оригинальные байты...
    // jmp обратно

    QByteArray code;
    // mov [imm32], eax : 0xA3 <imm32>
    code.append(char(0xA3));
    code.append(reinterpret_cast<const char*>(&m_savePtrAddress), 4);

    // Копируем оригинальные байты (m_originalBytes)
    code.append(m_originalBytes);

    // jmp обратно
    uintptr_t returnAddr = m_address + m_patchSize;
    code.append(char(0xE9));
    int32_t relJmp = static_cast<int32_t>(returnAddr - (m_trampolinePtr + code.size() + 4));
    code.append(reinterpret_cast<const char*>(&relJmp), 4);

    // Записываем трамплин в память процесса
    if (!m_memoryManager->writeMemory(m_trampolinePtr, code.data(), code.size()))
    {
        qCCritical(characterHookLog) << "Ошибка записи трамплина в память процесса!";
        return false;
    }

    qCInfo(characterHookLog) << "Трамплин CharacterHook успешно сгенерирован";
    return true;
}