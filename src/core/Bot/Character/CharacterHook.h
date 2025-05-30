#pragma once

#include "HookManager/Hook/InlineHook/InlineHook.h"
#include <QLoggingCategory>

/**
 * @brief Категория логирования для CharacterHook.
 */
Q_DECLARE_LOGGING_CATEGORY(characterHookLog)

/**
 * @brief Хук для перехвата указателя на структуру персонажа через EAX.
 *
 * После срабатывания хука значение EAX будет сохранено в выделенную память процесса,
 * а бот сможет прочитать этот адрес через MemoryManager.
 */
class CharacterHook : public InlineHook
{
   public:
    /**
     * @brief Конструктор CharacterHook.
     * @param address Адрес функции для перехвата (например, 0x57C6E0)
     * @param memoryManager Указатель на MemoryManager
     * @param savePtrAddress Адрес в памяти процесса, куда будет сохраняться EAX
     */
    CharacterHook(uintptr_t address, MemoryManager* memoryManager, uintptr_t savePtrAddress);

   protected:
    /**
     * @brief Генерация трамплина: сохраняет EAX в savePtrAddress, выполняет оригинальные байты, прыгает обратно.
     */
    bool generateTrampoline() override;

   private:
    uintptr_t m_savePtrAddress = 0;  ///< Куда сохранять EAX (выделенная память в run.exe)
};