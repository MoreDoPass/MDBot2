#pragma once
#include <QObject>
#include <QLoggingCategory>
#include <optional>

Q_DECLARE_LOGGING_CATEGORY(logCtm)

/**
 * @brief Класс для низкоуровневого управления Click To Move (CtM)
 * Аналог ClickToMove из Python-бота
 */
class CtmExecutor : public QObject
{
    Q_OBJECT
   public:
    explicit CtmExecutor(class MemoryManager* memory, QObject* parent = nullptr);
    ~CtmExecutor();

    /**
     * @brief Переместиться в точку
     */
    bool moveTo(float x, float y, float z, float distance = 0.3f);

    /**
     * @brief Атаковать цель
     */
    bool attack(float x, float y, float z, quint64 guid, float distance = 5.0f);

    /**
     * @brief Лутать объект
     */
    bool loot(float x, float y, float z, quint64 guid, float distance = 1.5f);

    /**
     * @brief Снять шкуру
     */
    bool skin(float x, float y, float z, quint64 guid, float distance = 1.5f);

    enum class ActionType : int
    {
        FACE_TARGET = 1,
        FACE = 2,
        MOVE_TO = 4,
        INTERACT_NPC = 5,
        LOOT = 6,
        INTERACT_OBJECT = 7,
        FACE_OTHER = 8,
        SKIN = 9,
        ATTACK_POSITION = 10,
        ATTACK_GUID = 11,
        CONSTANT_FACE = 12,
        NONE = 13,
        ATTACK = 16,
        IDLE = 19
    };

   private:
    /**
     * @brief Выполнить действие CtM
     */
    bool execute(ActionType action, float x, float y, float z, float distance,
                 std::optional<quint64> guid = std::nullopt);

    class MemoryManager* m_memory;
};
