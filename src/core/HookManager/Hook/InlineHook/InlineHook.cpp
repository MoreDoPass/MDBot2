#include "InlineHook.h"
#include <QLoggingCategory>
#include <capstone/capstone.h>

Q_LOGGING_CATEGORY(inlineHookLog, "mdbot2.inlinehook")

InlineHook::InlineHook(uintptr_t address, uintptr_t trampolinePtr, MemoryManager* memoryManager)
    : Hook(address), m_trampolinePtr(trampolinePtr), m_memoryManager(memoryManager)
{
    qCInfo(inlineHookLog) << "InlineHook создан для адреса" << Qt::hex << address;
}

InlineHook::~InlineHook()
{
    if (m_installed)
    {
        uninstall();
    }
}

bool InlineHook::install()
{
    try
    {
        if (!m_memoryManager)
        {
            qCCritical(inlineHookLog) << "MemoryManager не инициализирован!";
            return false;
        }

        if (!patch())
        {
            qCCritical(inlineHookLog) << "Ошибка патчинга функции";
            return false;
        }

        m_installed = true;
        qCInfo(inlineHookLog) << "InlineHook установлен на адрес" << Qt::hex << m_address;
        return true;
    }
    catch (const std::exception& ex)
    {
        qCCritical(inlineHookLog) << "Исключение при установке InlineHook:" << ex.what();
        return false;
    }
}

bool InlineHook::uninstall()
{
    try
    {
        if (!m_installed) return true;

        if (!restore())
        {
            qCCritical(inlineHookLog) << "Ошибка восстановления оригинальных байт";
            return false;
        }

        m_installed = false;
        qCInfo(inlineHookLog) << "InlineHook снят с адреса" << Qt::hex << m_address;
        return true;
    }
    catch (const std::exception& ex)
    {
        qCCritical(inlineHookLog) << "Исключение при снятии InlineHook:" << ex.what();
        return false;
    }
}

QString InlineHook::description() const
{
    return QString("InlineHook at 0x%1").arg(m_address, 0, 16);
}

size_t InlineHook::calculatePatchSize()
{
    QLoggingCategory capstoneLog("mdbot2.inlinehook.capstone");
    constexpr size_t kBufferSize = 32;
    QByteArray buffer(kBufferSize, 0);

    if (!m_memoryManager->readMemory(m_address, buffer.data(), buffer.size()))
    {
        qCCritical(capstoneLog) << "Ошибка чтения памяти по адресу" << Qt::hex << m_address;
        return 0;
    }

    csh handle;
    cs_insn* insn = nullptr;
    size_t offset = 0;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        qCCritical(capstoneLog) << "Capstone не открылся";
        return 0;
    }

    while (offset < 5)  // 5 байт — минимально для JMP x86
    {
        size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(buffer.data()) + offset, kBufferSize - offset,
                                 m_address + offset, 1, &insn);
        if (count == 0)
        {
            qCCritical(capstoneLog) << "Capstone не смог дизассемблировать по адресу" << Qt::hex
                                    << (m_address + offset);
            cs_close(&handle);
            return 0;
        }
        offset += insn[0].size;
        cs_free(insn, count);

        if (offset > kBufferSize)
        {
            qCCritical(capstoneLog) << "Размер патча превышает размер буфера!";
            cs_close(&handle);
            return 0;
        }
    }

    cs_close(&handle);
    return offset;
}

bool InlineHook::patch()
{
    // 1. Вычисляем безопасный размер патча (минимум 5 байт для JMP)
    m_patchSize = calculatePatchSize();
    if (m_patchSize < 5)
    {
        qCCritical(inlineHookLog) << "Недостаточный размер патча для JMP:" << m_patchSize;
        return false;
    }

    // 2. Сохраняем оригинальные байты
    m_originalBytes.resize(static_cast<int>(m_patchSize));
    if (!m_memoryManager->readMemory(m_address, m_originalBytes.data(), m_patchSize))
    {
        qCCritical(inlineHookLog) << "Ошибка чтения оригинальных байт по адресу" << Qt::hex << m_address;
        return false;
    }

    // 3. Выделяем память под трамплин (RWX)
    constexpr size_t trampolineSize = 64;
    m_trampolinePtr = reinterpret_cast<uintptr_t>(m_memoryManager->allocMemory(trampolineSize, PAGE_EXECUTE_READWRITE));
    if (!m_trampolinePtr)
    {
        qCCritical(inlineHookLog) << "Не удалось выделить память под трамплин";
        return false;
    }
    qCInfo(inlineHookLog) << "Память под трамплин выделена по адресу" << Qt::hex << m_trampolinePtr;

    // 4. Генерируем трамплин
    if (!generateTrampoline())
    {
        qCCritical(inlineHookLog) << "Ошибка генерации трамплина";
        return false;
    }

    // 5. Меняем защиту памяти оригинальной функции на RWX
    DWORD oldProt = 0;
    if (!m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize,
                                                 PAGE_EXECUTE_READWRITE, &oldProt))
    {
        qCCritical(inlineHookLog) << "Ошибка смены защиты памяти по адресу" << Qt::hex << m_address;
        return false;
    }

    // 6. Формируем и записываем патч (JMP на трамплин + NOP)
    QByteArray patchBytes;
    patchBytes.resize(static_cast<int>(m_patchSize));

    // JMP (E9) + relative address
    patchBytes[0] = static_cast<char>(0xE9);
    int32_t relAddr = static_cast<int32_t>(m_trampolinePtr - (m_address + 5));
    memcpy(patchBytes.data() + 1, &relAddr, 4);

    // Fill rest with NOPs
    for (size_t i = 5; i < m_patchSize; ++i)
    {
        patchBytes[i] = static_cast<char>(0x90);
    }

    if (!m_memoryManager->writeMemory(m_address, patchBytes.data(), m_patchSize))
    {
        qCCritical(inlineHookLog) << "Ошибка записи JMP-патча по адресу" << Qt::hex << m_address;
        m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize, oldProt);
        return false;
    }

    // 7. Восстанавливаем защиту памяти
    m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize, oldProt);
    return true;
}

bool InlineHook::restore()
{
    if (!m_installed)
    {
        qCInfo(inlineHookLog) << "Хук уже снят или не был установлен";
        return true;
    }

    if (m_originalBytes.isEmpty() || m_patchSize == 0)
    {
        qCCritical(inlineHookLog) << "Нет сохранённых оригинальных байт для восстановления";
        return false;
    }

    DWORD oldProt = 0;
    if (!m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize,
                                                 PAGE_EXECUTE_READWRITE, &oldProt))
    {
        qCCritical(inlineHookLog) << "Ошибка смены защиты памяти при восстановлении по адресу" << Qt::hex << m_address;
        return false;
    }

    if (!m_memoryManager->writeMemory(m_address, m_originalBytes.constData(), m_patchSize))
    {
        qCCritical(inlineHookLog) << "Ошибка восстановления оригинальных байт по адресу" << Qt::hex << m_address;
        m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize, oldProt);
        return false;
    }

    m_memoryManager->changeMemoryProtection(reinterpret_cast<void*>(m_address), m_patchSize, oldProt);
    return true;
}