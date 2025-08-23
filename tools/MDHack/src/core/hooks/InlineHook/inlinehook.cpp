#include "inlinehook.h"
#include <windows.h>
#include <cstring>
#include <capstone/capstone.h>

// Функция для подсчёта безопасного размера патча с помощью Capstone
size_t calcSafePatchSize(MemoryManager& mem, uintptr_t address, size_t minSize)
{
    uint8_t buffer[32] = {0};
    if (!mem.read(address, buffer, sizeof(buffer))) return 0;
    csh handle;
    cs_insn* insn;
    size_t offset = 0;
    size_t count;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        qDebug() << "Capstone не открылся";
        return 0;
    }
    while (offset < minSize)
    {
        count = cs_disasm(handle, buffer + offset, 16, address + offset, 1, &insn);
        if (count == 0)
        {
            qDebug() << "Capstone не смог дизассемблировать по адресу" << QString::number(address + offset, 16);
            cs_close(&handle);
            return 0;
        }
        offset += insn[0].size;
        cs_free(insn, count);
    }
    cs_close(&handle);
    return offset;
}

InlineHook::InlineHook(void* addr, InlineHookCallback cb, MemoryManager& mem, int size)
    : memoryManager(mem), targetAddr(addr), callback(cb), installed(false), trampoline(nullptr)
{
    // Автоматически определяем безопасный patchSize через Capstone
    patchSize = calcSafePatchSize(memoryManager, (uintptr_t)addr, size);
    memset(originalBytes, 0, sizeof(originalBytes));
}

InlineHook::~InlineHook()
{
    remove();
    if (trampoline)
    {
        memoryManager.freeEx(trampoline);  // Освобождаем память в wow.exe
    }
}

bool InlineHook::install()
{
    if (installed) return false;
    // Сохраняем оригинальные байты из wow.exe
    memoryManager.read((uintptr_t)targetAddr, originalBytes, patchSize);
    if (!createTrampoline()) return false;
    // Ставим JMP на наш обработчик в wow.exe
    writeJump(targetAddr, trampoline);
    installed = true;
    return true;
}

bool InlineHook::remove()
{
    if (!installed) return false;
    // Восстанавливаем оригинальные байты в wow.exe
    DWORD oldProtect;
    memoryManager.protectEx((uintptr_t)targetAddr, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memoryManager.write((uintptr_t)targetAddr, originalBytes, patchSize);
    memoryManager.protectEx((uintptr_t)targetAddr, patchSize, oldProtect, &oldProtect);
    installed = false;
    return true;
}

bool InlineHook::isInstalled() const
{
    return installed;
}

bool InlineHook::createTrampoline()
{
    // Выделяем память под трамплин в wow.exe
    trampoline = memoryManager.allocEx(patchSize + 5);
    if (!trampoline) return false;
    // Копируем оригинальные байты из wow.exe в трамплин (через WriteProcessMemory)
    uint8_t orig[32] = {0};
    memoryManager.read((uintptr_t)targetAddr, orig, patchSize);
    memoryManager.write((uintptr_t)trampoline, orig, patchSize);
    // Добавляем JMP обратно в функцию после патча
    uint8_t jmpBack[5] = {0xE9};
    uintptr_t src = (uintptr_t)trampoline + patchSize;
    uintptr_t dst = (uintptr_t)targetAddr + patchSize;
    *(uint32_t*)(jmpBack + 1) = (uint32_t)(dst - (src + 5));
    memoryManager.write(src, jmpBack, 5);
    return true;
}

void InlineHook::writeJump(void* from, void* to)
{
    DWORD oldProtect;
    // Меняем защиту памяти в wow.exe через VirtualProtectEx
    memoryManager.protectEx((uintptr_t)from, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    // Пишем JMP через WriteProcessMemory
    uint8_t patch[16] = {0};
    patch[0] = 0xE9;
    *(uint32_t*)(patch + 1) = (uint32_t)((uint8_t*)to - ((uint8_t*)from + 5));
    for (int i = 5; i < patchSize; ++i) patch[i] = 0x90;
    memoryManager.write((uintptr_t)from, patch, patchSize);
    // Восстанавливаем защиту
    memoryManager.protectEx((uintptr_t)from, patchSize, oldProtect, &oldProtect);
}

// Пример callback-а:
// void MyHookCallback(uint32_t* pEax) {
//     printf("EAX = %08X\n", *pEax);
// }
