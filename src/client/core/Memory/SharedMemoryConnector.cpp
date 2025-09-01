#include "SharedMemoryConnector.h"

SharedMemoryConnector::SharedMemoryConnector() = default;
SharedMemoryConnector::~SharedMemoryConnector()
{
    close();
}

bool SharedMemoryConnector::open(const std::wstring& name, size_t size)
{
    // 1. Открываем существующий мьютекс
    m_hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, (name + L"_Mutex").c_str());
    if (m_hMutex == NULL) return false;

    // 2. Открываем существующий file mapping
    m_hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name.c_str());
    if (m_hMapFile == NULL)
    {
        CloseHandle(m_hMutex);
        return false;
    }

    // 3. Отображаем view
    m_pSharedMem = MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, size);
    if (m_pSharedMem == nullptr)
    {
        CloseHandle(m_hMapFile);
        CloseHandle(m_hMutex);
        return false;
    }
    return true;
}

void SharedMemoryConnector::close()
{
    if (m_pSharedMem) UnmapViewOfFile(m_pSharedMem);
    if (m_hMapFile) CloseHandle(m_hMapFile);
    if (m_hMutex) CloseHandle(m_hMutex);
    m_pSharedMem = nullptr;
    m_hMapFile = NULL;
    m_hMutex = NULL;
}

bool SharedMemoryConnector::write(const SharedData& data)
{
    if (!m_pSharedMem || !m_hMutex) return false;
    if (WaitForSingleObject(m_hMutex, 100) == WAIT_OBJECT_0)
    {
        memcpy(m_pSharedMem, &data, sizeof(SharedData));
        ReleaseMutex(m_hMutex);
        return true;
    }
    return false;
}