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

    /**
     * @brief Получить прямой указатель на структуру SharedData в общей памяти.
     * @details Позволяет напрямую читать и изменять данные.
     *          ВНИМАНИЕ: Доступ к этому указателю должен быть синхронизирован
     *          вручную (например, через мьютекс), если это необходимо.
     *          В нашем случае (один писатель - MDBot2, один читатель - DLL)
     *          для простых полей это безопасно.
     * @return Указатель на SharedData или nullptr, если память не создана.
     */
    SharedData* getMemoryPtr();

    /**
     * @brief Получить КОНСТАНТНЫЙ прямой указатель на структуру SharedData.
     * @details Позволяет напрямую БЕЗОПАСНО читать данные. Любая попытка
     *          изменить данные через этот указатель вызовет ошибку компиляции.
     * @return Константный указатель на SharedData или nullptr.
     */
    const SharedData* getConstMemoryPtr() const;  // <-- Добавляем const в конце

   private:
    HANDLE m_hMapFile = NULL;      ///< Handle для file mapping
    HANDLE m_hMutex = NULL;        ///< Handle для мьютекса синхронизации
    void* m_pSharedMem = nullptr;  ///< Указатель на начало общей памяти
    size_t m_size = 0;             ///< Размер блока памяти
};