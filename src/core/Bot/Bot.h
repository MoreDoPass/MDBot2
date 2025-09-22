#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <QThread>
#include <QString>
#include <memory>  // Для std::unique_ptr

#include "core/MemoryManager/MemoryManager.h"
#include "core/HookManager/HookManager.h"
#include "core/Bot/Character/Character.h"
#include "core/Bot/Movement/MovementManager.h"
#include "core/Bot/GameObjectManager/GameObjectManager.h"
#include "core/bot/CombatManager/CombatManager.h"
#include "core/SharedMemoryManager/SharedMemoryManager.h"
#include "core/Bot/InteractionManager/InteractionManager.h"
#include "Shared/Data/SharedData.h"

#include "core/Bot/Settings/BotSettings.h"

// Прямое объявление, чтобы не включать полный заголовок
class ProfileManager;
class GetComputerNameHook;
class BTNode;
class BTContext;
class QTimer;

/**
 * @brief Класс Bot — основной класс для управления одним персонажем WoW.
 */
class Bot : public QObject
{
    Q_OBJECT
   public:
    explicit Bot(qint64 processId, const QString& processName, const QString& computerNameToSet,
                 QObject* parent = nullptr);
    ~Bot();

    qint64 processId() const;
    Character* character() const;
    MovementManager* movementManager() const;
    GameObjectManager* gameObjectManager() const;
    CombatManager* combatManager() const;
    InteractionManager* interactionManager() const;

    /**
     * @brief Возвращает GUID текущей цели, которую выбрало дерево поведения.
     * @details Этот метод является "мостом" для GUI, позволяя безопасно
     *          получить информацию о текущей цели бота для дальнейших действий,
     *          например, для добавления в черный список.
     * @return GUID цели или 0, если цель не выбрана.
     */
    quint64 getCurrentTargetGuid() const;

   public slots:
    void start(const BotStartSettings& settings, ProfileManager* profileManager);
    void stop();
    void provideDebugData();

   signals:
    void finished();
    void debugDataReady(const SharedData& data);

   private slots:
    /**
     * @brief Основной цикл работы бота. Этот метод выполняется в отдельном потоке.
     */
    void tick();

   private:
    qint64 m_processId;             ///< PID процесса WoW
    QString m_processName;          ///< Имя процесса (run.exe, Wow.exe)
    MemoryManager m_memoryManager;  ///< Объект MemoryManager для работы с памятью
    HookManager m_hookManager;
    Character* m_character = nullptr;

    MovementManager* m_movementManager = nullptr;
    GameObjectManager* m_gameObjectManager = nullptr;
    CombatManager* m_combatManager = nullptr;
    InteractionManager* m_interactionManager = nullptr;

    bool m_running = false;
    QThread* m_thread = nullptr;

    QTimer* m_tickTimer = nullptr;  ///< Таймер, который будет задавать "пульс" работы бота.

    std::unique_ptr<GetComputerNameHook> m_computerNameHook;
    SharedMemoryManager m_sharedMemory;
    std::wstring m_sharedMemoryName;

    std::unique_ptr<BTNode> m_behaviorTreeRoot;
    std::unique_ptr<BTContext> m_btContext;
    BotStartSettings m_currentSettings;
};
Q_DECLARE_LOGGING_CATEGORY(logBot)

// ОБЪЯВЛЯЕМ общую категорию для всех узлов Дерева Поведения.
// Все "кирпичики" будут подключать Bot.h, чтобы "узнать" об этой категории.
Q_DECLARE_LOGGING_CATEGORY(logBT)