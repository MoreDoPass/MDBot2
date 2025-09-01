#pragma once
#include "shared/Data/SharedData.h"
#include <windows.h>
#include <string>

/**
 * @class SharedMemoryConnector
 * @brief Подключается к существующему блоку общей памяти.
 *
 * Предназначен для использования внутри DLL.
 */
class SharedMemoryConnector
{
   public:
    SharedMemoryConnector();
    ~SharedMemoryConnector();

    bool open(const std::wstring& name, size_t size);
    void close();
    bool write(const SharedData& data);

   private:
    HANDLE m_hMapFile = NULL;
    HANDLE m_hMutex = NULL;
    void* m_pSharedMem = nullptr;
};