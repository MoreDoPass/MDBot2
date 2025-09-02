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

    /**
     * @brief Открыть существующий блок общей памяти.
     * @param name Имя блока памяти.
     * @param size Размер блока.
     * @return true в случае успеха.
     */
    bool open(const std::wstring& name, size_t size);

    /**
     * @brief Закрыть соединение с общей памятью.
     */
    void close();

    /**
     * @brief Получить прямой указатель на структуру SharedData в общей памяти.
     * @details Позволяет как читать, так и писать данные.
     * @return Указатель на SharedData или nullptr, если память не открыта.
     */
    SharedData* getMemoryPtr();

    /**
     * @brief Записать данные в общую память (потокобезопасно).
     * @deprecated Рекомендуется использовать getMemoryPtr() для прямого доступа.
     *             Этот метод оставлен для обратной совместимости.
     * @param data Структура с данными для записи.
     * @return true в случае успеха.
     */
    bool write(const SharedData& data);

   private:
    HANDLE m_hMapFile = NULL;
    HANDLE m_hMutex = NULL;
    void* m_pRawMem = nullptr;  // Изменено имя для ясности
};