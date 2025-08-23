#pragma once

#include "core/HookManager/Hook/InlineHook/InlineHook.h"
#include <QLoggingCategory>

/**
 * @brief Категория логирования для TeleportStepFlagHook.
 * @details Используется для вывода отладочной информации и ошибок, связанных с этим хуком.
 */
Q_DECLARE_LOGGING_CATEGORY(logTeleportHook)

/**
 * @class TeleportStepFlagHook
 * @brief Хук для пошаговой телепортации в WoW 3.3.5a.
 * @details Этот хук ставится на функцию, которая вызывается при движении персонажа.
 * Его задача - проверить, совпадает ли указатель на структуру игрока в регистре ECX
 * с реальным указателем на нашего игрока. Если да, то он записывает байт '1' в специальный
 * "флаговый" буфер в памяти игры. Основная логика телепорта затем ждет появления этого флага,
 * чтобы понять, что игра "приняла" новые координаты и можно делать следующий шаг.
 */
class TeleportStepFlagHook : public InlineHook
{
   public:
    /**
     * @brief Конструктор хука для пошаговой телепортации.
     * @param address Адрес функции в памяти игры, на которую ставится хук (например, 0x7413F0).
     * @param playerStructAddrBuffer Адрес в памяти игры, где хранится актуальный указатель на структуру игрока.
     *                               Хук будет сравнивать ECX с содержимым этого адреса.
     * @param flagBuffer Адрес в памяти игры, куда будет записан байт '1' при успешном срабатывании.
     * @param memoryManager Указатель на MemoryManager для работы с памятью целевого процесса.
     */
    TeleportStepFlagHook(uintptr_t address, uintptr_t playerStructAddrBuffer, uintptr_t flagBuffer,
                         MemoryManager* memoryManager);

    /**
     * @brief Деструктор по умолчанию.
     */
    ~TeleportStepFlagHook() override = default;

    /**
     * @brief Получить строковое описание хука.
     * @return Описание хука.
     */
    QString description() const override;

   protected:
    /**
     * @brief Генерирует и записывает в память игры трамплин (shellcode) для хука.
     * @details Код трамплина выполняет следующие действия:
     * 1. Сравнивает значение регистра ECX с указателем на структуру игрока.
     * 2. Если они не равны, переходит к выполнению оригинального кода.
     * 3. Если они равны, записывает 1 в 'flagBuffer'.
     * 4. Выполняет оригинальные инструкции, которые были затерты патчем.
     * 5. Возвращается к выполнению оригинальной функции.
     * @return true, если трамплин успешно сгенерирован и записан.
     */
    bool generateTrampoline() override;

   private:
    /// @brief Адрес в памяти игры, где хранится указатель на структуру игрока.
    uintptr_t m_playerStructAddrBuffer = 0;
    /// @brief Адрес в памяти игры, куда записывается флаг '1' при срабатывании.
    uintptr_t m_flagBuffer = 0;
};