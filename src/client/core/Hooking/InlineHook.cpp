#include "InlineHook.h"
#include <windows.h>

InlineHook::InlineHook(uintptr_t address) : m_address(address) {}

InlineHook::~InlineHook()
{
    uninstall();
}

bool InlineHook::install()
{
    if (m_installed || m_address == 0) return false;

    m_patchSize = calculatePatchSize();
    if (m_patchSize == 0) return false;

    // 1. Создаем трамплин (как и раньше)
    m_originalBytes.resize(m_patchSize);
    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)m_address, m_originalBytes.data(), m_patchSize, nullptr) == 0)
    {
        return false;  // Не удалось прочитать память
    }
    m_trampoline = VirtualAlloc(nullptr, m_patchSize + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!m_trampoline) return false;
    memcpy(m_trampoline, m_originalBytes.data(), m_patchSize);
    uint8_t* trampolineBytes = (uint8_t*)m_trampoline;
    trampolineBytes[m_patchSize] = 0xE9;  // JMP
    *(uintptr_t*)(trampolineBytes + m_patchSize + 1) =
        (m_address + m_patchSize) - ((uintptr_t)m_trampoline + m_patchSize + 5);

    // 2. Создаем наш ассемблерный обработчик в памяти
    m_handlerStub = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!m_handlerStub)
    {
        VirtualFree(m_trampoline, 0, MEM_RELEASE);
        m_trampoline = nullptr;
        return false;
    }

    uint8_t* stubBytes = (uint8_t*)m_handlerStub;
    size_t stubSize = 0;

    // PUSHFD - сохранить флаги
    stubBytes[stubSize++] = 0x9C;
    // PUSHAD - сохранить все регистры (EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI)
    stubBytes[stubSize++] = 0x60;

    // --- КЛЮЧЕВОЕ ИЗМЕНЕНИЕ ---
    // Готовим вызов CppBridge(this, &regs). Аргументы передаются в стек справа налево.

    // PUSH ESP - передаем второй аргумент (указатель на структуру Registers, которая сейчас на вершине стека)
    stubBytes[stubSize++] = 0x54;
    // PUSH this - передаем первый аргумент (указатель на наш объект)
    stubBytes[stubSize++] = 0x68;
    *(uintptr_t*)(stubBytes + stubSize) = (uintptr_t)this;
    stubSize += 4;

    // CALL CppBridge
    stubBytes[stubSize++] = 0xE8;
    *(uintptr_t*)(stubBytes + stubSize) = (uintptr_t)CppBridge - ((uintptr_t)m_handlerStub + stubSize + 4);
    stubSize += 4;
    // CppBridge имеет соглашение __stdcall, поэтому он сам очистит стек от аргументов (8 байт).

    // POPAD - восстановить все регистры
    stubBytes[stubSize++] = 0x61;
    // POPFD - восстановить флаги
    stubBytes[stubSize++] = 0x9D;

    // JMP на трамплин
    stubBytes[stubSize++] = 0xE9;
    *(uintptr_t*)(stubBytes + stubSize) = (uintptr_t)m_trampoline - ((uintptr_t)m_handlerStub + stubSize + 4);
    stubSize += 4;

    // 3. Устанавливаем JMP-патч на наш обработчик
    DWORD oldProtect;
    VirtualProtect((void*)m_address, m_patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    uint8_t patch[5] = {0xE9};
    *(uintptr_t*)(patch + 1) = (uintptr_t)m_handlerStub - (m_address + 5);
    memcpy((void*)m_address, patch, 5);
    for (size_t i = 5; i < m_patchSize; ++i)
    {
        *(uint8_t*)(m_address + i) = 0x90;  // NOP
    }
    VirtualProtect((void*)m_address, m_patchSize, oldProtect, &oldProtect);

    m_installed = true;
    return true;
}

void InlineHook::uninstall()
{
    if (!m_installed) return;
    DWORD oldProtect;
    VirtualProtect((void*)m_address, m_patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)m_address, m_originalBytes.data(), m_patchSize);
    VirtualProtect((void*)m_address, m_patchSize, oldProtect, &oldProtect);

    if (m_trampoline)
    {
        VirtualFree(m_trampoline, 0, MEM_RELEASE);
        m_trampoline = nullptr;
    }
    if (m_handlerStub)
    {
        VirtualFree(m_handlerStub, 0, MEM_RELEASE);
        m_handlerStub = nullptr;
    }
    m_installed = false;
}

size_t InlineHook::calculatePatchSize()
{
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) return 0;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn;
    size_t count = cs_disasm(handle, (const uint8_t*)m_address, 20, m_address, 0, &insn);
    if (count == 0)
    {
        cs_close(&handle);
        return 0;
    }

    size_t totalSize = 0;
    for (size_t i = 0; i < count; ++i)
    {
        // Нельзя патчить инструкции, которые делают относительные переходы,
        // так как мы не пересчитываем их адреса. Пропускаем их.
        // Это упрощение, в идеале нужно было бы их исправлять.
        if (insn[i].id == X86_INS_JMP || insn[i].id == X86_INS_CALL ||
            (insn[i].id >= X86_INS_JAE && insn[i].id <= X86_INS_JS))
        {
            if (insn[i].detail->x86.operands[0].type == X86_OP_IMM)
            {
                // Если это относительный переход, мы не можем его безопасно переместить.
                // Прерываем подсчет здесь.
                break;
            }
        }

        totalSize += insn[i].size;
        if (totalSize >= 5) break;
    }

    cs_free(insn, count);
    cs_close(&handle);
    return totalSize >= 5 ? totalSize : 0;
}

// Наш "мост" из ASM в C++. Это обычная статическая функция.
void __stdcall InlineHook::CppBridge(InlineHook* self, const Registers* regs)
{
    if (self)
    {
        self->handler(regs);
    }
}