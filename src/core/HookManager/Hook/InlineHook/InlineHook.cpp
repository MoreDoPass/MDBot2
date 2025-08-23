#include "core/HookManager/Hook/InlineHook/InlineHook.h"
#include <QLoggingCategory>
#include <capstone/capstone.h>

/**
 * @brief Категория логирования для InlineHook.
 */
Q_LOGGING_CATEGORY(inlineHookLog, "mdbot2.inlinehook")

/**
 * @brief Конструктор InlineHook.
 * @param address Адрес функции для перехвата.
 * @param trampolinePtr Адрес обработчика (куда будет прыгать jmp). В нашей архитектуре
 *                      этот адрес выделяется автоматически в методе patch(), поэтому здесь можно передавать 0.
 * @param memoryManager Указатель на MemoryManager для работы с памятью.
 */
InlineHook::InlineHook(uintptr_t address, uintptr_t trampolinePtr, MemoryManager* memoryManager)
    : Hook(address), m_trampolinePtr(trampolinePtr), m_memoryManager(memoryManager)
{
    // Комментарии и документация остаются на русском. Вывод в консоль - на английском.
    qCInfo(inlineHookLog) << "InlineHook created for address" << Qt::hex << address;
}

/**
 * @brief Деструктор.
 * @details Важно: деструктор больше не вызывает uninstall() автоматически.
 * Управлением временем жизни хука (установка/снятие) должен заниматься владеющий им класс, например, AppContext.
 * Это предотвращает случайное снятие хука, когда локальный unique_ptr выходит из области видимости.
 */
InlineHook::~InlineHook()
{
    // Старый код с автоматическим uninstall() удален.
    // Если хук был установлен, его нужно будет снять вручную через вызов uninstall().
    if (m_installed)
    {
        qCWarning(inlineHookLog) << "InlineHook at" << Qt::hex << m_address
                                 << "is being destroyed while still installed. This might be a memory leak.";
    }
}

/**
 * @brief Устанавливает хук.
 * @return true, если хук успешно установлен.
 */
bool InlineHook::install()
{
    try
    {
        if (m_installed)
        {
            qCWarning(inlineHookLog) << "Hook at" << Qt::hex << m_address << "is already installed.";
            return true;
        }

        if (!m_memoryManager)
        {
            qCCritical(inlineHookLog) << "MemoryManager is not initialized!";
            return false;
        }

        if (!patch())
        {
            qCCritical(inlineHookLog) << "Failed to patch function.";
            return false;
        }

        m_installed = true;
        qCInfo(inlineHookLog) << "InlineHook installed at address" << Qt::hex << m_address;
        return true;
    }
    catch (const std::exception& ex)
    {
        qCCritical(inlineHookLog) << "Exception during InlineHook installation:" << ex.what();
        return false;
    }
}

/**
 * @brief Снимает хук.
 * @return true, если хук успешно снят или не был установлен.
 */
bool InlineHook::uninstall()
{
    try
    {
        if (!m_installed) return true;

        if (!restore())
        {
            qCCritical(inlineHookLog) << "Failed to restore original bytes.";
            return false;
        }

        m_installed = false;
        qCInfo(inlineHookLog) << "InlineHook uninstalled from address" << Qt::hex << m_address;
        return true;
    }
    catch (const std::exception& ex)
    {
        qCCritical(inlineHookLog) << "Exception during InlineHook uninstallation:" << ex.what();
        return false;
    }
}

/**
 * @brief Возвращает строковое описание хука.
 * @return Строка с описанием.
 */
QString InlineHook::description() const
{
    return QString("InlineHook at 0x%1").arg(m_address, 0, 16);
}

/**
 * @brief Вычисляет безопасный размер для патча с использованием Capstone.
 * @return Размер в байтах, достаточный для размещения jmp, или 0 при ошибке.
 */
size_t InlineHook::calculatePatchSize()
{
    QLoggingCategory capstoneLog("mdbot2.inlinehook.capstone");
    qCDebug(capstoneLog) << "--- Calculating patch size for address" << Qt::hex << m_address << "---";

    constexpr size_t minPatchSize = 5;  // Минимальный размер для JMP rel32
    constexpr size_t kBufferSize = 32;
    QByteArray buffer(kBufferSize, 0);

    if (!m_memoryManager->readMemory(m_address, buffer.data(), buffer.size()))
    {
        qCCritical(capstoneLog) << "ERROR: Failed to read process memory at" << Qt::hex << m_address;
        return 0;
    }

    qCDebug(capstoneLog) << "Read bytes:" << buffer.toHex(' ');

    csh handle;
    cs_insn* insn = nullptr;
    size_t total_size = 0;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        qCCritical(capstoneLog) << "ERROR: Failed to open Capstone handle.";
        return 0;
    }

    qCDebug(capstoneLog) << "Starting disassembly loop (target size >=" << minPatchSize << ")";

    while (total_size < minPatchSize)
    {
        size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(buffer.data()) + total_size,
                                 kBufferSize - total_size, m_address + total_size, 1, &insn);
        if (count == 0)
        {
            qCCritical(capstoneLog) << "ERROR: Capstone failed to disassemble at address" << Qt::hex
                                    << (m_address + total_size);
            cs_close(&handle);
            return 0;
        }

        qCDebug(capstoneLog) << "Instruction:" << insn[0].mnemonic << insn[0].op_str << "| Address:" << Qt::hex
                             << insn[0].address << "| Size:" << insn[0].size;

        total_size += insn[0].size;
        qCDebug(capstoneLog) << "Current total size:" << total_size;

        cs_free(insn, count);
    }

    cs_close(&handle);
    qCInfo(capstoneLog) << "--- Successfully calculated patch size:" << total_size << "---";
    return total_size;
}

/**
 * @brief Выполняет основную работу по установке хука.
 * @return true, если успешно.
 */
bool InlineHook::patch()
{
    // 1. Вычисляем безопасный размер патча.
    m_patchSize = calculatePatchSize();
    if (m_patchSize == 0)
    {
        qCCritical(inlineHookLog) << "Calculated patch size is 0. Aborting.";
        return false;
    }
    if (m_patchSize < 5)
    {
        qCCritical(inlineHookLog) << "Patch size" << m_patchSize << "is less than minimum required 5 bytes.";
        return false;
    }

    // 2. Сохраняем оригинальные байты.
    m_originalBytes.resize(static_cast<int>(m_patchSize));
    if (!m_memoryManager->readMemory(m_address, m_originalBytes.data(), m_patchSize))
    {
        qCCritical(inlineHookLog) << "Failed to read original bytes at address" << Qt::hex << m_address;
        return false;
    }

    // 3. Выделяем память под трамплин.
    constexpr size_t trampolineSize = 64;  // С запасом
    void* remoteMem = m_memoryManager->allocMemory(trampolineSize, PAGE_EXECUTE_READWRITE);
    if (!remoteMem)
    {
        qCCritical(inlineHookLog) << "Failed to allocate memory for trampoline.";
        return false;
    }
    m_trampolinePtr = reinterpret_cast<uintptr_t>(remoteMem);
    qCInfo(inlineHookLog) << "Allocated memory for trampoline at" << Qt::hex << m_trampolinePtr;

    // 4. Генерируем трамплин.
    if (!generateTrampoline())
    {
        qCCritical(inlineHookLog) << "Failed to generate trampoline.";
        m_memoryManager->freeMemory(remoteMem);  // Освобождаем память
        m_trampolinePtr = 0;
        return false;
    }

    // 5. Меняем защиту памяти на основной функции.
    DWORD oldProt = 0;
    if (!m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize,
                                                 PAGE_EXECUTE_READWRITE, &oldProt))
    {
        qCCritical(inlineHookLog) << "Failed to change memory protection at" << Qt::hex << m_address;
        m_memoryManager->freeMemory(remoteMem);  // Освобождаем память
        m_trampolinePtr = 0;
        return false;
    }

    // 6. Формируем и записываем патч (JMP + NOPs).
    QByteArray patchBytes;
    patchBytes.resize(static_cast<int>(m_patchSize));
    patchBytes.fill('\x90');  // Заполняем NOP-ами

    // JMP (E9) + относительный адрес
    patchBytes[0] = static_cast<char>(0xE9);
    int32_t relAddr = static_cast<int32_t>(m_trampolinePtr - (m_address + 5));
    memcpy(patchBytes.data() + 1, &relAddr, 4);

    if (!m_memoryManager->writeMemory(m_address, patchBytes.data(), m_patchSize))
    {
        qCCritical(inlineHookLog) << "Failed to write JMP patch to address" << Qt::hex << m_address;
        m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize, oldProt, nullptr);
        return false;
    }

    // 7. Восстанавливаем оригинальную защиту памяти.
    m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize, oldProt, nullptr);
    return true;
}

/**
 * @brief Восстанавливает оригинальные байты, снимая хук.
 * @return true, если успешно.
 */
bool InlineHook::restore()
{
    if (m_originalBytes.isEmpty() || m_patchSize == 0)
    {
        qCCritical(inlineHookLog) << "No original bytes saved, cannot restore.";
        return false;
    }

    DWORD oldProt = 0;
    if (!m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize,
                                                 PAGE_EXECUTE_READWRITE, &oldProt))
    {
        qCCritical(inlineHookLog) << "Failed to change memory protection for restoration at" << Qt::hex << m_address;
        return false;
    }

    if (!m_memoryManager->writeMemory(m_address, m_originalBytes.constData(), m_patchSize))
    {
        qCCritical(inlineHookLog) << "Failed to restore original bytes at" << Qt::hex << m_address;
        m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize, oldProt, nullptr);
        return false;
    }

    // Освобождаем память, выделенную под трамплин
    if (m_trampolinePtr != 0)
    {
        m_memoryManager->freeMemory(reinterpret_cast<void*>(m_trampolinePtr));
        m_trampolinePtr = 0;
    }

    m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize, oldProt, nullptr);
    return true;
}