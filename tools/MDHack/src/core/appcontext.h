#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <QString>
#include "core/player/player.h"

// --- Подключаем общие компоненты из ядра MDBot2 (с правильными путями) ---
#include "core/MemoryManager/MemoryManager.h"
#include "core/HookManager/HookManager.h"
#include "core/Bot/Movement/Teleport/TeleportExecutor.h"
#include "core/Bot/Movement/Teleport/TeleportStepFlagHook.h"

// --- Подключаем наши "личные" хуки из локальной папки ---
#include "core/hooks/CharacterHook.h"
#include "core/hooks/TargetHook.h"

// Прямые объявления
class GetComputerNameHook;
class GameObject;  // Вместо #include "core/Bot/GameObjectManager/Structures/GameObject.h"

/**
 * @class AppContext
 * @brief Основной класс-контекст для приложения MDHack.
 */
class AppContext
{
   public:
    AppContext();
    ~AppContext();

    bool attachToProcess(uint32_t pid, const std::wstring& processName, const QString& computerNameToSet);
    void detach();
    bool isAttached() const;
    uint32_t getPid() const;
    TeleportExecutor* getTeleportExecutor() const;
    std::optional<Player> getPlayer();
    GameObject* getTargetObject();
    uintptr_t getTeleportFlagBufferAddress() const;
    MemoryManager* getMemoryManager() const
    {
        return m_memoryManager.get();
    }

   private:
    // --- Основные менеджеры из MDBot2 ---
    std::unique_ptr<MemoryManager> m_memoryManager;
    std::unique_ptr<HookManager> m_hookManager;
    std::unique_ptr<TeleportExecutor> m_teleportExecutor;

    // --- "Личные" хуки MDHack ---
    std::unique_ptr<GetComputerNameHook> m_computerNameHook;
    std::unique_ptr<CharacterHook> m_characterHook;
    std::unique_ptr<TargetHook> m_targetHook;
    std::unique_ptr<TeleportStepFlagHook> m_teleportHook;

    // --- Буферы в памяти игры для хранения указателей ---
    void* m_playerPtrBuffer = nullptr;
    void* m_targetPtrBuffer = nullptr;
    void* m_teleportFlagBuffer = nullptr;

    /// @brief PID подключенного процесса.
    uint32_t m_pid = 0;
};