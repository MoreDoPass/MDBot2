#pragma once
#include "Shared/Data/SharedData.h"  // Наш "контракт"
#include <windows.h>
#include <string>

/**
 * @class SharedMemoryManager
 * @brief Управляет созданием и доступом к блоку общей памяти (Shared Memory).
 *
 * Этот класс отвечает за создание File Mapping и Mutex, а также предоставляет
 * потокобезопасные методы для чтения и записи данных.
 * Экземпляр этого класса должен создаваться в основном приложении (MDBot2.exe).
 */
class SharedMemoryManager
{
   public:
    SharedMemoryManager();
    ~SharedMemoryManager();

    /**
     * @brief Создает (или открывает существующий) блок общей памяти.
     * @param name Уникальное имя для блока памяти и мьютекса.
     * @param size Размер блока памяти в байтах.
     * @return true в случае успеха, иначе false.
     */
    bool create(const std::wstring& name, size_t size);

    /**
     * @brief Закрывает и освобождает все ресурсы.
     */
    void close();

    /**
     * @brief Безопасно читает данные из общей памяти.
     * @param data Структура, в которую будут скопированы данные.
     * @return true в случае успеха, иначе false.
     */
    bool read(SharedData& data);

    /**
     * @brief Безопасно записывает данные в общую память.
     * @param data Структура с данными для записи.
     * @return true в случае успеха, иначе false.
     */
    bool write(const SharedData& data);

   private:
    HANDLE m_hMapFile = NULL;      ///< Handle для file mapping
    HANDLE m_hMutex = NULL;        ///< Handle для мьютекса синхронизации
    void* m_pSharedMem = nullptr;  ///< Указатель на начало общей памяти
    size_t m_size = 0;             ///< Размер блока памяти
};