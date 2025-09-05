#include "TargetHook.h"
#include <QLoggingCategory>

/**
 * @brief Категория логирования для TargetHook.
 */
Q_LOGGING_CATEGORY(targetHookLog, "mdbot.targethook")

/**
 * @brief Конструктор TargetHook.
 * @param address Адрес функции для перехвата.
 * @param memoryManager Указатель на MemoryManager.
 * @param savePtrAddress Адрес в памяти процесса, куда будет сохраняться указатель из ESI.
 */
TargetHook::TargetHook(uintptr_t address, MemoryManager* memoryManager, uintptr_t savePtrAddress)
    // Вызываем конструктор базового класса. trampolinePtr = 0, т.к. мы выделяем его сами.
    : InlineHook(address, 0, memoryManager), m_savePtrAddress(savePtrAddress)
{
    qCInfo(targetHookLog) << "TargetHook created for address" << Qt::hex << address << "to save ESI at" << Qt::hex
                          << savePtrAddress;
}

/**
 * @brief Генерирует трамплин: сохраняет ESI в m_savePtrAddress,
 *          выполняет оригинальные байты и прыгает обратно в код игры.
 * @return true, если трамплин успешно сгенерирован и записан.
 */
bool TargetHook::generateTrampoline()
{
    if (!m_trampolinePtr || !m_savePtrAddress || !m_memoryManager)
    {
        qCCritical(targetHookLog) << "Cannot generate trampoline: one of the required pointers is null!";
        return false;
    }

    // Здесь мы будем собирать наш шеллкод
    QByteArray shellcode;

    // --- Ключевое отличие от CharacterHook ---
    // Нам нужно сохранить регистр ESI. Инструкция для этого: mov [address], esi
    // В опкодах это: 89 35 [адрес, 4 байта]
    shellcode.append(static_cast<char>(0x89));
    shellcode.append(static_cast<char>(0x35));
    shellcode.append(reinterpret_cast<const char*>(&m_savePtrAddress), sizeof(uintptr_t));
    qCDebug(targetHookLog) << "Generated shellcode for 'mov [addr], esi'";

    // Копируем оригинальные байты, которые были затерты нашим JMP'ом.
    // m_originalBytes и m_patchSize уже были подготовлены в базовом классе InlineHook::patch().
    shellcode.append(m_originalBytes);
    qCDebug(targetHookLog) << "Appended" << m_originalBytes.size() << "original bytes";

    // --- Расчет JMP для возврата в оригинальный код ---
    // Адрес, куда мы должны вернуться в игре (сразу после наших затертых байт).
    const uintptr_t returnAddr = m_address + m_patchSize;
    // Адрес, с которого будет выполняться наш JMP в трамплине.
    const uintptr_t jmpSrcAddr = m_trampolinePtr + shellcode.size();
    // Вычисляем относительное смещение для JMP (E9).
    const int32_t relativeAddr = static_cast<int32_t>(returnAddr - (jmpSrcAddr + 5));

    // Добавляем инструкцию jmp в шеллкод: E9 [смещение, 4 байта]
    shellcode.append(static_cast<char>(0xE9));
    shellcode.append(reinterpret_cast<const char*>(&relativeAddr), sizeof(int32_t));
    qCDebug(targetHookLog) << "Appended jmp back to" << Qt::hex << returnAddr;

    // Записываем весь сгенерированный шеллкод в память процесса по адресу трамплина
    // --- ИЗМЕНЕНИЕ ЗДЕСЬ ---
    // Передаем m_trampolinePtr как uintptr_t, как того требует MemoryManager::writeMemory
    if (!m_memoryManager->writeMemory(m_trampolinePtr, shellcode.constData(), shellcode.size()))
    {
        qCCritical(targetHookLog) << "Failed to write trampoline shellcode to process memory at" << Qt::hex
                                  << m_trampolinePtr;
        return false;
    }

    qCInfo(targetHookLog) << "TargetHook trampoline of size" << shellcode.size() << "generated successfully at"
                          << Qt::hex << m_trampolinePtr;
    return true;
}