#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include "core/player/player.h"

// --- Подключаем компоненты из ядра MDBot2 ---
#include "core/MemoryManager/MemoryManager.h"
#include "core/HookManager/HookManager.h"
#include "core/Bot/Movement/Teleport/TeleportExecutor.h"
#include "core/Bot/Character/CharacterHook.h"
#include "core/Bot/Movement/Teleport/TeleportStepFlagHook.h"

/**
 * @class AppContext
 * @brief Основной класс-контекст для приложения MDHack.
 * @details Инкапсулирует всю логику взаимодействия с целевым процессом игры:
 * управляет менеджерами памяти и хуков, создает и устанавливает необходимые хуки
 * для получения данных и выполнения телепортации. Использует core-библиотеки из MDBot2.
 */
class AppContext
{
   public:
    /**
     * @brief Конструктор.
     */
    AppContext();

    /**
     * @brief Деструктор. Автоматически отключается от процесса.
     */
    ~AppContext();

    /**
     * @brief Подключиться к процессу по его PID.
     * @details Создает и инициализирует все необходимые менеджеры и хуки.
     * @param pid Идентификатор процесса WoW.
     * @param processName Имя процесса (например, L"run.exe").
     * @return true в случае успеха, иначе false.
     */
    bool attachToProcess(uint32_t pid, const std::wstring& processName);

    /**
     * @brief Отключиться от процесса.
     * @details Освобождает все ресурсы и закрывает хендл процесса.
     */
    void detach();

    /**
     * @brief Проверить, активно ли подключение к процессу.
     * @return true, если подключение активно.
     */
    bool isAttached() const;

    /**
     * @brief Получить PID подключенного процесса.
     * @return PID процесса или 0, если не подключен.
     */
    uint32_t getPid() const;

    /**
     * @brief Получить экземпляр исполнителя телепортации.
     * @return Указатель на TeleportExecutor или nullptr.
     */
    TeleportExecutor* getTeleportExecutor() const;

    /**
     * @brief Получить объект Player для чтения/записи координат.
     * @details Сначала получает актуальный указатель на структуру игрока,
     * а затем создает на его основе объект-обертку Player.
     * @return std::optional<Player>, который может быть пустым, если указатель еще не получен.
     */
    std::optional<Player> getPlayer();

    /**
     * @brief Получить адрес буфера, куда хук записывает флаг шага телепортации.
     * @return Адрес буфера.
     */
    uintptr_t getTeleportFlagBufferAddress() const;

   private:
    /// @brief Указатель на менеджер памяти из MDBot2.
    std::unique_ptr<MemoryManager> m_memoryManager;
    /// @brief Указатель на менеджер хуков из MDBot2.
    std::unique_ptr<HookManager> m_hookManager;
    /// @brief Указатель на исполнителя телепортации из MDBot2.
    std::unique_ptr<TeleportExecutor> m_teleportExecutor;

    /// @brief PID подключенного процесса.
    uint32_t m_pid = 0;
    /// @brief Адрес в памяти игры, куда CharacterHook сохраняет указатель на структуру игрока.
    void* m_playerPtrBuffer = nullptr;
    /// @brief Адрес в памяти игры, куда TeleportStepFlagHook сохраняет флаг '1'.
    void* m_teleportFlagBuffer = nullptr;
};