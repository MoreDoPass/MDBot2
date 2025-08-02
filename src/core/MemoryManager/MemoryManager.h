#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <windows.h>
#include <optional>
#include <string>  // Для std::wstring

Q_DECLARE_LOGGING_CATEGORY(memoryManagerLog)

/**
 * @brief Класс для работы с памятью внешнего процесса (например, WoW)
 *
 * Позволяет открывать процесс по PID, читать и писать память, логировать действия.
 */
class MemoryManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор MemoryManager
     * @param parent Родительский QObject
     */
    explicit MemoryManager(QObject* parent = nullptr);

    /**
     * @brief Деструктор MemoryManager. Закрывает процесс, если он был открыт.
     */
    ~MemoryManager();

    /**
     * @brief Открыть процесс по PID и имени его главного модуля.
     * @param pid Идентификатор процесса.
     * @param mainModuleName Имя главного исполняемого файла (например, L"run.exe").
     * @return true, если процесс успешно открыт.
     */
    bool openProcess(DWORD pid, const std::wstring& mainModuleName);

    /**
     * @brief Закрыть процесс (если был открыт)
     */
    void closeProcess();

    /**
     * @brief Проверить, открыт ли процесс
     * @return true, если процесс открыт
     */
    bool isProcessOpen() const;

    /**
     * @brief Получить PID открытого процесса
     * @return PID или std::nullopt, если процесс не открыт
     */
    std::optional<DWORD> pid() const;

    /**
     * @brief Получить базовый адрес главного модуля текущего процесса.
     * @return Базовый адрес или 0 при ошибке.
     */
    uintptr_t getMainModuleBaseAddress();

    /**
     * @brief Универсальный шаблонный метод для чтения значения любого типа из памяти процесса.
     * @tparam T Тип данных (int, float, double, структура и т.д.)
     * @param address Абсолютный адрес в памяти процесса
     * @param value Ссылка, куда будет записан результат
     * @return true, если чтение успешно
     */
    template <typename T>
    bool readMemory(uintptr_t address, T& value)
    {
        try
        {
            if (!m_processHandle)
            {
                qCCritical(memoryManagerLog) << "Попытка чтения памяти при неоткрытом процессе!";
                return false;
            }
            SIZE_T bytesRead = 0;
            BOOL result =
                ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), &bytesRead);
            if (!result || bytesRead != sizeof(T))
            {
                // Уменьшаем критичность лога, т.к. чтение по "мусорному" адресу - частая ситуация
                // qCCritical(memoryManagerLog)
                //     << "Ошибка чтения памяти по адресу" << Qt::hex << address << ", код ошибки:" << GetLastError();
                return false;
            }
            return true;
        }
        catch (const std::exception& ex)
        {
            qCCritical(memoryManagerLog) << "Исключение в readMemory:" << ex.what();
            return false;
        }
    }

    /**
     * @brief Метод для чтения строки (char-массива) из памяти процесса.
     * @param address Абсолютный адрес в памяти процесса
     * @param buffer Указатель на буфер, куда будет записана строка
     * @param size Размер буфера (количество байт для чтения)
     * @return true, если чтение успешно
     */
    bool readMemory(uintptr_t address, char* buffer, size_t size)
    {
        try
        {
            if (!m_processHandle)
            {
                qCCritical(memoryManagerLog) << "Попытка чтения строки при неоткрытом процессе!";
                return false;
            }
            SIZE_T bytesRead = 0;
            BOOL result =
                ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead);
            if (!result || bytesRead != size)
            {
                // qCCritical(memoryManagerLog)
                //     << "Ошибка чтения строки по адресу" << Qt::hex << address << ", код ошибки:" << GetLastError();
                return false;
            }
            return true;
        }
        catch (const std::exception& ex)
        {
            qCCritical(memoryManagerLog) << "Исключение в readMemory (string):" << ex.what();
            return false;
        }
    }

    /**
     * @brief Универсальный шаблонный метод для записи значения любого типа в память процесса.
     * @tparam T Тип данных (int, float, double, структура и т.д.)
     * @param address Абсолютный адрес в памяти процесса
     * @param value Значение для записи
     * @return true, если запись успешна
     */
    template <typename T>
    bool writeMemory(uintptr_t address, const T& value)
    {
        try
        {
            if (!m_processHandle)
            {
                qCCritical(memoryManagerLog) << "Попытка записи памяти при неоткрытом процессе!";
                return false;
            }
            SIZE_T bytesWritten = 0;
            BOOL result = WriteProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), &value, sizeof(T),
                                             &bytesWritten);
            if (!result || bytesWritten != sizeof(T))
            {
                qCCritical(memoryManagerLog)
                    << "Ошибка записи памяти по адресу" << Qt::hex << address << ", код ошибки:" << GetLastError();
                return false;
            }
            return true;
        }
        catch (const std::exception& ex)
        {
            qCCritical(memoryManagerLog) << "Исключение в writeMemory:" << ex.what();
            return false;
        }
    }

    /**
     * @brief Метод для записи строки (char-массива) в память процесса.
     * @param address Абсолютный адрес в памяти процесса
     * @param buffer Указатель на буфер с записываемой строкой
     * @param size Размер буфера (количество байт для записи)
     * @return true, если запись успешна
     */
    bool writeMemory(uintptr_t address, const char* buffer, size_t size)
    {
        try
        {
            if (!m_processHandle)
            {
                qCCritical(memoryManagerLog) << "Попытка записи строки при неоткрытом процессе!";
                return false;
            }
            SIZE_T bytesWritten = 0;
            BOOL result =
                WriteProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), buffer, size, &bytesWritten);
            if (!result || bytesWritten != size)
            {
                qCCritical(memoryManagerLog)
                    << "Ошибка записи строки по адресу" << Qt::hex << address << ", код ошибки:" << GetLastError();
                return false;
            }
            return true;
        }
        catch (const std::exception& ex)
        {
            qCCritical(memoryManagerLog) << "Исключение в writeMemory (string):" << ex.what();
            return false;
        }
    }

    /**
     * @brief Выделить память во внешнем процессе
     * @param size Размер в байтах
     * @param protection Защита памяти (по умолчанию RWX)
     * @return Указатель на выделенную память или nullptr при ошибке
     */
    void* allocMemory(size_t size, DWORD protection = PAGE_EXECUTE_READWRITE);

    /**
     * @brief Освободить ранее выделенную память во внешнем процессе
     * @param address Указатель на память
     * @return true, если память успешно освобождена
     */
    bool freeMemory(void* address);

    /**
     * @brief Изменить защиту участка памяти во внешнем процессе
     * @param address Указатель на память
     * @param size Размер участка
     * @param newProtection Новая защита (например, PAGE_EXECUTE_READWRITE)
     * @param oldProtection [out] Предыдущая защита (опционально)
     * @return true, если успешно
     */
    bool changeMemoryProtection(void* address, size_t size, DWORD newProtection, DWORD* oldProtection = nullptr);

   private:
    /**
     * @brief Находит базовый адрес модуля в процессе. Вспомогательный метод.
     * @param moduleName Имя модуля для поиска.
     * @return Базовый адрес или 0.
     */
    uintptr_t findModuleBaseAddress(const std::wstring& moduleName);

   protected:
    HANDLE m_processHandle = nullptr;
    DWORD m_pid = 0;
    std::wstring m_mainModuleName;          ///< Имя главного модуля (run.exe, Wow.exe)
    uintptr_t m_mainModuleBaseAddress = 0;  ///< Кэшированный базовый адрес главного модуля
};
