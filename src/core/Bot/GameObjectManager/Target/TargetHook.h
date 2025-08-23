#pragma once

#include "core/HookManager/Hook/InlineHook/InlineHook.h"
#include <QLoggingCategory>

/**
 * @brief Категория логирования для TargetHook.
 */
Q_DECLARE_LOGGING_CATEGORY(targetHookLog)

/**
 * @class TargetHook
 * @brief Хук для перехвата указателя на структуру текущей цели через регистр ESI.
 * @details После срабатывания хука, значение регистра ESI (который, как предполагается,
 *          содержит указатель на объект цели) будет сохранено в специально выделенную
 *          область памяти. GameObjectManager затем сможет прочитать этот адрес.
 */
class TargetHook : public InlineHook
{
   public:
    /**
     * @brief Конструктор TargetHook.
     * @param address Адрес функции для перехвата (например, 0x0072A6C5).
     * @param memoryManager Указатель на MemoryManager.
     * @param savePtrAddress Адрес в памяти процесса, куда будет сохраняться указатель из ESI.
     */
    TargetHook(uintptr_t address, MemoryManager* memoryManager, uintptr_t savePtrAddress);

   protected:
    /**
     * @brief Генерирует трамплин: сохраняет ESI в m_savePtrAddress,
     *          выполняет оригинальные байты и прыгает обратно в код игры.
     * @return true, если трамплин успешно сгенерирован и записан.
     */
    bool generateTrampoline() override;

   private:
    /// @brief Адрес в памяти целевого процесса, куда мы сохраняем указатель на цель.
    uintptr_t m_savePtrAddress = 0;
};