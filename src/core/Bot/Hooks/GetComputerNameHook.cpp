#include "GetComputerNameHook.h"
#include <QLoggingCategory>
#include <windows.h>  // Для GetProcAddress, GetModuleHandle

Q_LOGGING_CATEGORY(getComputerNameHookLog, "core.hook.getcomputername")

// Инициализируем статический член. 0 означает, что адрес еще не найден.
uintptr_t GetComputerNameHook::m_GetComputerNameA_addr = 0;

GetComputerNameHook::GetComputerNameHook(MemoryManager* memoryManager, const std::string& fakeComputerName)
    // 1. Динамически находим адрес GetComputerNameA
    : InlineHook((m_GetComputerNameA_addr != 0) ? m_GetComputerNameA_addr
                                                : (m_GetComputerNameA_addr = reinterpret_cast<uintptr_t>(GetProcAddress(
                                                       GetModuleHandleA("kernel32.dll"), "GetComputerNameA"))),
                 0, memoryManager),
      m_fakeComputerName(fakeComputerName)
{
    if (m_GetComputerNameA_addr == 0)
    {
        qCCritical(getComputerNameHookLog) << "Failed to get address of GetComputerNameA!";
        // Бросаем исключение, т.к. без адреса хук бесполезен
        throw std::runtime_error("Could not find GetComputerNameA address.");
    }

    // 2. Выделяем память в целевом процессе под нашу строку + 1 байт для null-терминатора
    m_remoteStringPtr = m_memoryManager->allocMemory(m_fakeComputerName.length() + 1);
    if (!m_remoteStringPtr)
    {
        qCCritical(getComputerNameHookLog) << "Failed to allocate memory for fake name in target process!";
        throw std::runtime_error("Failed to allocate remote memory for string.");
    }

    // 3. Записываем наше имя в эту выделенную память
    if (!m_memoryManager->writeMemory(reinterpret_cast<uintptr_t>(m_remoteStringPtr), m_fakeComputerName.c_str(),
                                      m_fakeComputerName.length() + 1))
    {
        qCCritical(getComputerNameHookLog) << "Failed to write fake name to target process!";
        m_memoryManager->freeMemory(m_remoteStringPtr);  // Чистим за собой
        m_remoteStringPtr = nullptr;
        throw std::runtime_error("Failed to write remote string.");
    }

    qCInfo(getComputerNameHookLog) << "GetComputerNameHook created. Fake name"
                                   << QString::fromStdString(m_fakeComputerName) << "written to" << Qt::hex
                                   << m_remoteStringPtr;
}

GetComputerNameHook::~GetComputerNameHook()
{
    // Деструктор сам по себе не снимает хук, но если мы забыли это сделать,
    // он освободит память, чтобы избежать утечек в процессе игры.
    if (m_remoteStringPtr && m_memoryManager)
    {
        m_memoryManager->freeMemory(m_remoteStringPtr);
    }
    qCInfo(getComputerNameHookLog) << "GetComputerNameHook destroyed.";
}

bool GetComputerNameHook::uninstall()
{
    // Сначала вызываем базовый метод, который снимает JMP-патч и освобождает память трамплина
    bool result = InlineHook::uninstall();

    // Затем освобождаем память, которую мы выделили под нашу строку
    if (m_remoteStringPtr && m_memoryManager)
    {
        if (!m_memoryManager->freeMemory(m_remoteStringPtr))
        {
            qCWarning(getComputerNameHookLog) << "Failed to free remote string memory at" << m_remoteStringPtr;
            result = false;
        }
        else
        {
            qCInfo(getComputerNameHookLog) << "Successfully freed remote string memory.";
        }
        m_remoteStringPtr = nullptr;
    }
    return result;
}

bool GetComputerNameHook::generateTrampoline()
{
    if (!m_trampolinePtr || !m_memoryManager || !m_remoteStringPtr)
    {
        qCCritical(getComputerNameHookLog) << "Cannot generate trampoline: required pointers are null.";
        return false;
    }

    QByteArray shellcode;
    const uint32_t nameLength = static_cast<uint32_t>(m_fakeComputerName.length());
    const uint32_t nameLengthWithNull = nameLength + 1;
    const uintptr_t remoteStringAddr = reinterpret_cast<uintptr_t>(m_remoteStringPtr);

    // --- Самодостаточный шеллкод ---

    // pushad - сохраняем все регистры
    shellcode.append(static_cast<char>(0x60));

    // mov edi, [esp + 0x24] ; Загружаем в EDI указатель на буфер (lpBuffer)
    shellcode.append(static_cast<char>(0x8B));
    shellcode.append(static_cast<char>(0x7C));
    shellcode.append(static_cast<char>(0x24));
    shellcode.append(static_cast<char>(0x24));  // смещение = 32 (pushad) + 4 (адрес возврата) = 36 = 0x24

    // mov esi, remoteStringAddr ; Загружаем в ESI адрес НАШЕЙ строки в памяти игры
    shellcode.append(static_cast<char>(0xBE));
    shellcode.append(reinterpret_cast<const char*>(&remoteStringAddr), sizeof(remoteStringAddr));

    // mov ecx, nameLengthWithNull ; Загружаем в ECX количество байт для копирования
    shellcode.append(static_cast<char>(0xB9));
    shellcode.append(reinterpret_cast<const char*>(&nameLengthWithNull), sizeof(nameLengthWithNull));

    // rep movsb ; Копируем ECX байт из [ESI] в [EDI]
    shellcode.append(static_cast<char>(0xF3));
    shellcode.append(static_cast<char>(0xA4));

    // mov ebx, [esp + 0x28] ; Загружаем в EBX указатель на переменную размера (nSize)
    shellcode.append(static_cast<char>(0x8B));
    shellcode.append(static_cast<char>(0x5C));
    shellcode.append(static_cast<char>(0x24));
    shellcode.append(static_cast<char>(0x28));  // смещение = 32 (pushad) + 8 (lpBuffer + ret_addr) = 40 = 0x28

    // mov [ebx], nameLength ; Записываем в nSize длину нашего имени (без null)
    shellcode.append(static_cast<char>(0xC7));
    shellcode.append(static_cast<char>(0x03));
    shellcode.append(reinterpret_cast<const char*>(&nameLength), sizeof(nameLength));

    // popad - восстанавливаем все регистры
    shellcode.append(static_cast<char>(0x61));

    // mov eax, 1 - возвращаем TRUE (успех)
    shellcode.append(static_cast<char>(0xB8));
    uint32_t ret_val = 1;
    shellcode.append(reinterpret_cast<const char*>(&ret_val), sizeof(ret_val));

    // ret 8 - выходим из функции и чистим 8 байт (2 аргумента) со стека
    shellcode.append(static_cast<char>(0xC2));
    shellcode.append(static_cast<char>(0x08));
    shellcode.append(static_cast<char>(0x00));

    // --- Запись шеллкода в память игры ---
    if (!m_memoryManager->writeMemory(m_trampolinePtr, shellcode.constData(), shellcode.size()))
    {
        qCCritical(getComputerNameHookLog) << "Failed to write trampoline shellcode to" << Qt::hex << m_trampolinePtr;
        return false;
    }

    qCInfo(getComputerNameHookLog) << "Self-contained trampoline generated successfully at" << Qt::hex
                                   << m_trampolinePtr;
    return true;
}