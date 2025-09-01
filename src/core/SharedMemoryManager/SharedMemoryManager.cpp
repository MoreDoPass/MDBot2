#include "SharedMemoryManager.h"
#include <stdexcept>

SharedMemoryManager::SharedMemoryManager() = default;

SharedMemoryManager::~SharedMemoryManager()
{
    close();
}

bool SharedMemoryManager::create(const std::wstring& name, size_t size)
{
    if (m_hMapFile)  // Если уже создано, сначала закрываем
    {
        close();
    }
    m_size = size;

    // 1. Создаем мьютекс для синхронизации доступа
    m_hMutex = CreateMutexW(NULL, FALSE, (name + L"_Mutex").c_str());
    if (m_hMutex == NULL)
    {
        return false;
    }

    // 2. Создаем file mapping
    m_hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE,      // Используем файл подкачки
                                    NULL,                      // Атрибуты безопасности по умолчанию
                                    PAGE_READWRITE,            // Права на чтение/запись
                                    0,                         // Старший DWORD размера
                                    static_cast<DWORD>(size),  // Младший DWORD размера
                                    name.c_str()               // Имя объекта
    );

    if (m_hMapFile == NULL)
    {
        CloseHandle(m_hMutex);
        m_hMutex = NULL;
        return false;
    }

    // 3. Отображаем view на память
    m_pSharedMem = MapViewOfFile(m_hMapFile,           // Handle на file mapping
                                 FILE_MAP_ALL_ACCESS,  // Права на чтение/запись
                                 0, 0, size);

    if (m_pSharedMem == nullptr)
    {
        CloseHandle(m_hMapFile);
        CloseHandle(m_hMutex);
        m_hMapFile = NULL;
        m_hMutex = NULL;
        return false;
    }

    return true;
}

void SharedMemoryManager::close()
{
    if (m_pSharedMem)
    {
        UnmapViewOfFile(m_pSharedMem);
        m_pSharedMem = nullptr;
    }
    if (m_hMapFile)
    {
        CloseHandle(m_hMapFile);
        m_hMapFile = NULL;
    }
    if (m_hMutex)
    {
        CloseHandle(m_hMutex);
        m_hMutex = NULL;
    }
}

bool SharedMemoryManager::read(SharedData& data)
{
    if (!m_pSharedMem || !m_hMutex) return false;

    // Ждем, пока мьютекс освободится (максимум 100 мс)
    if (WaitForSingleObject(m_hMutex, 100) == WAIT_OBJECT_0)
    {
        // Копируем данные из общей памяти
        memcpy(&data, m_pSharedMem, sizeof(SharedData));

        // Освобождаем мьютекс
        ReleaseMutex(m_hMutex);
        return true;
    }
    return false;  // Не дождались мьютекса
}

bool SharedMemoryManager::write(const SharedData& data)
{
    if (!m_pSharedMem || !m_hMutex) return false;

    if (WaitForSingleObject(m_hMutex, 100) == WAIT_OBJECT_0)
    {
        // Копируем данные в общую память
        memcpy(m_pSharedMem, &data, sizeof(SharedData));

        ReleaseMutex(m_hMutex);
        return true;
    }
    return false;
}