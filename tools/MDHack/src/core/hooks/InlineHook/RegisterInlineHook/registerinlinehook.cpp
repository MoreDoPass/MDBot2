#include "registerinlinehook.h"
#include <cstring>

// Пример только для EDI (x86)
// Генерирует shellcode: mov [bufferAddr], edi; ...оригинальные инструкции...; jmp назад
RegisterInlineHook::RegisterInlineHook(void* addr, const char* regName, uintptr_t bufferAddr, MemoryManager& mem,
                                       int minPatchSize)
    : InlineHook(addr, nullptr, mem, minPatchSize), regName(regName), bufferAddr(bufferAddr)
{
}

// Переопределяем создание трамплина
bool RegisterInlineHook::createTrampoline()
{
    // Поддерживаем основные 32-битные регистры x86
    int maxShellcodeSize = 16 + patchSize + 5;  // запас
    // 1. СНАЧАЛА выделяем память под трамплин и сохраняем адрес
    trampoline = memoryManager.allocEx(maxShellcodeSize);
    if (!trampoline) return false;

    uint8_t shellcode[64] = {0};
    int offset = 0;
    if (strcmp(regName, "edi") == 0)
    {
        // mov [bufferAddr], edi: 89 3D <addr>
        shellcode[0] = 0x89;
        shellcode[1] = 0x3D;
        *(uint32_t*)(shellcode + 2) = (uint32_t)bufferAddr;
        offset = 6;
    }
    else if (strcmp(regName, "esi") == 0)
    {
        // mov [bufferAddr], esi: 89 35 <addr>
        shellcode[0] = 0x89;
        shellcode[1] = 0x35;
        *(uint32_t*)(shellcode + 2) = (uint32_t)bufferAddr;
        offset = 6;
    }
    else if (strcmp(regName, "ebx") == 0)
    {
        // mov [bufferAddr], ebx: 89 1D <addr>
        shellcode[0] = 0x89;
        shellcode[1] = 0x1D;
        *(uint32_t*)(shellcode + 2) = (uint32_t)bufferAddr;
        offset = 6;
    }
    else if (strcmp(regName, "edx") == 0)
    {
        // mov [bufferAddr], edx: 89 15 <addr>
        shellcode[0] = 0x89;
        shellcode[1] = 0x15;
        *(uint32_t*)(shellcode + 2) = (uint32_t)bufferAddr;
        offset = 6;
    }
    else if (strcmp(regName, "ecx") == 0)
    {
        // mov [bufferAddr], ecx: 89 0D <addr>
        shellcode[0] = 0x89;
        shellcode[1] = 0x0D;
        *(uint32_t*)(shellcode + 2) = (uint32_t)bufferAddr;
        offset = 6;
    }
    else if (strcmp(regName, "eax") == 0)
    {
        // mov [bufferAddr], eax: A3 <addr>
        shellcode[0] = 0xA3;
        *(uint32_t*)(shellcode + 1) = (uint32_t)bufferAddr;
        offset = 5;
    }
    else
    {
        return false;
    }
    // Копируем оригинальные инструкции (patchSize байт)
    memoryManager.read((uintptr_t)targetAddr, shellcode + offset, patchSize);
    offset += patchSize;
    // jmp назад: E9 <rel32>
    shellcode[offset] = 0xE9;
    uintptr_t src = (uintptr_t)trampoline + offset;
    uintptr_t dst = (uintptr_t)targetAddr + patchSize;
    *(uint32_t*)(shellcode + offset + 1) = (uint32_t)(dst - (src + 5));
    offset += 5;
    // Пишем shellcode в wow.exe
    memoryManager.write((uintptr_t)trampoline, shellcode, offset);
    return true;
}
