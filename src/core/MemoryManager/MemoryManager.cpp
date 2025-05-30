#include "MemoryManager.h"
#include <QDebug>

Q_LOGGING_CATEGORY(memoryManagerLog, "core.memorymanager")

MemoryManager::MemoryManager(QObject* parent) : QObject(parent)
{
    qCInfo(memoryManagerLog) << "MemoryManager создан";
}

MemoryManager::~MemoryManager()
{
    closeProcess();
    qCInfo(memoryManagerLog) << "MemoryManager уничтожен";
}

bool MemoryManager::openProcess(DWORD pid)
{
    closeProcess();
    m_processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!m_processHandle)
    {
        qCCritical(memoryManagerLog) << "Не удалось открыть процесс" << pid << ", ошибка:" << GetLastError();
        m_pid = 0;
        return false;
    }
    m_pid = pid;
    qCInfo(memoryManagerLog) << "Процесс открыт, PID:" << pid;
    return true;
}

void MemoryManager::closeProcess()
{
    if (m_processHandle)
    {
        if (!CloseHandle(m_processHandle))
        {
            qCCritical(memoryManagerLog) << "Ошибка при закрытии дескриптора процесса, PID:" << m_pid
                                         << ", ошибка:" << GetLastError();
        }
        else
        {
            qCInfo(memoryManagerLog) << "Процесс закрыт, PID:" << m_pid;
        }
        m_processHandle = nullptr;
        m_pid = 0;
    }
}

bool MemoryManager::isProcessOpen() const
{
    return m_processHandle != nullptr;
}

std::optional<DWORD> MemoryManager::pid() const
{
    if (m_processHandle) return m_pid;
    return std::nullopt;
}

void* MemoryManager::allocMemory(size_t size, DWORD protection)
{
    if (!m_processHandle) {
        qCCritical(memoryManagerLog) << "Попытка выделения памяти при неоткрытом процессе!";
        return nullptr;
    }
    void* remoteAddr = VirtualAllocEx(m_processHandle, nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
    if (!remoteAddr) {
        qCCritical(memoryManagerLog) << "Ошибка выделения памяти в процессе, код ошибки:" << GetLastError();
        return nullptr;
    }
    qCInfo(memoryManagerLog) << "Память выделена в процессе по адресу" << remoteAddr << ", размер:" << size;
    return remoteAddr;
}

bool MemoryManager::freeMemory(void* address)
{
    if (!m_processHandle) {
        qCCritical(memoryManagerLog) << "Попытка освобождения памяти при неоткрытом процессе!";
        return false;
    }
    if (!address) {
        qCCritical(memoryManagerLog) << "Попытка освобождения nullptr!";
        return false;
    }
    BOOL result = VirtualFreeEx(m_processHandle, address, 0, MEM_RELEASE);
    if (!result) {
        qCCritical(memoryManagerLog) << "Ошибка освобождения памяти по адресу" << address << ", код ошибки:" << GetLastError();
        return false;
    }
    qCInfo(memoryManagerLog) << "Память освобождена по адресу" << address;
    return true;
}

bool MemoryManager::changeMemoryProtection(void* address, size_t size, DWORD newProtection, DWORD* oldProtection)
{
    if (!m_processHandle) {
        qCCritical(memoryManagerLog) << "Попытка смены защиты памяти при неоткрытом процессе!";
        return false;
    }
    if (!address || size == 0) {
        qCCritical(memoryManagerLog) << "Некорректные параметры для смены защиты памяти!";
        return false;
    }
    DWORD oldProt = 0;
    BOOL result = VirtualProtectEx(m_processHandle, address, size, newProtection, &oldProt);
    if (!result) {
        qCCritical(memoryManagerLog) << "Ошибка смены защиты памяти по адресу" << address << ", код ошибки:" << GetLastError();
        return false;
    }
    if (oldProtection) *oldProtection = oldProt;
    qCInfo(memoryManagerLog) << "Защита памяти изменена по адресу" << address << ", новая защита:" << newProtection;
    return true;
}
