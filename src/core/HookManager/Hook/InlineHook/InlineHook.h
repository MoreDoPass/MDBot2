#ifndef INLINEHOOK_H
#define INLINEHOOK_H

#include "HookManager/Hook/Hook.h"
#include <QLoggingCategory>
#include "MemoryManager/MemoryManager.h"

/**
 * @brief Класс для реализации inline (trampoline) хука.
 * Позволяет перехватывать выполнение функции по адресу, вставляя jmp на свой обработчик.
 */
class InlineHook : public Hook
{
   public:
    /**
     * @brief Конструктор InlineHook
     * @param address Адрес функции для перехвата
     * @param trampolinePtr Адрес обработчика (куда будет прыгать jmp)
     * @param memoryManager Указатель на MemoryManager для работы с памятью
     */
    InlineHook(uintptr_t address, uintptr_t trampolinePtr, MemoryManager* memoryManager);
    ~InlineHook() override;

    bool install() override;
    bool uninstall() override;
    QString description() const override;

   protected:
    /**
     * @brief Генерирует трамплин для хука.
     * @details Каждый наследник должен реализовать свою логику генерации трамплина.
     * @return true, если генерация успешна.
     */
    virtual bool generateTrampoline() = 0;  // Теперь pure virtual

    MemoryManager* m_memoryManager;  ///< Указатель на MemoryManager
    uintptr_t m_trampolinePtr = 0;   ///< Адрес обработчика (куда прыгает jmp)
    size_t m_patchSize = 0;          ///< Размер патча (сколько байт заменяем)
    QByteArray m_originalBytes;      ///< Оригинальные байты функции

   private:
    /**
     * @brief Вычислить необходимый размер патча для jmp
     * @return Размер патча в байтах
     */
    size_t calculatePatchSize();

    /**
     * @brief Пропатчить функцию (записать jmp)
     * @return true, если успешно
     */
    bool patch();

    /**
     * @brief Восстановить оригинальные байты
     * @return true, если успешно
     */
    bool restore();
};

Q_DECLARE_LOGGING_CATEGORY(inlineHookLog)

#endif  // INLINEHOOK_H