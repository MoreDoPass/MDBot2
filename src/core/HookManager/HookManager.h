#ifndef HOOKMANAGER_H
#define HOOKMANAGER_H

#include <QObject>
#include <QLoggingCategory>
#include <QMap>
#include <QByteArray>
#include <QMutex>
#include <cstdint>
#include "MemoryManager/MemoryManager.h"

Q_DECLARE_LOGGING_CATEGORY(hookManagerLog)

/**
 * @brief Класс для управления хуками в процессе WoW.
 * Позволяет устанавливать, снимать и отслеживать хуки на функции по адресу.
 * Не является синглтоном — каждый бот/модуль может иметь свой экземпляр.
 */
class HookManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор класса HookManager
     * @param parent Родительский QObject
     */
    explicit HookManager(QObject* parent = nullptr);
    explicit HookManager(MemoryManager* memoryManager);
    /**
     * @brief Деструктор класса HookManager
     */
    ~HookManager();

    /**
     * @brief Установить хук на функцию по адресу
     * @param address Адрес функции
     * @param callback Указатель на функцию-обработчик (пользовательские данные)
     * @param hookType Тип хука (пока не используется)
     * @return true, если успешно, иначе false
     */
    bool addHook(uintptr_t address, void* callback, int hookType = 0);

    /**
     * @brief Снять хук с функции по адресу
     * @param address Адрес функции
     * @return true, если успешно, иначе false
     */
    bool removeHook(uintptr_t address);

    /**
     * @brief Проверить, установлен ли хук на адрес
     * @param address Адрес функции
     * @return true, если хук установлен
     */
    bool isHooked(uintptr_t address) const;

    /**
     * @brief Получить оригинальные байты функции
     * @param address Адрес функции
     * @return QByteArray с оригинальными байтами, пустой если нет
     */
    QByteArray getOriginalBytes(uintptr_t address) const;

    /**
     * @brief Снять все хуки
     * @return true, если успешно, иначе false
     */
    bool clearAllHooks();

   private:
    struct HookInfo
    {
        void* callback;
        QByteArray originalBytes;
        int hookType;
    };
    QMap<uintptr_t, HookInfo> m_hooks;
    mutable QMutex m_mutex;
    MemoryManager* m_memoryManager;
};

#endif  // HOOKMANAGER_H
