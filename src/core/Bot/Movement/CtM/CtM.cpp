#include "CtM.h"
#include "core/MemoryManager/MemoryManager.h"
#include <QLoggingCategory>
#include <QtGlobal>
#include <array>

Q_LOGGING_CATEGORY(logCtm, "mdbot.ctm")

// Адреса для WoW 3.3.5a Sirus (примерные, могут отличаться!)
constexpr uintptr_t CTM_X_COORD = 0xCA1264;
constexpr uintptr_t CTM_Y_COORD = 0xCA1268;
constexpr uintptr_t CTM_Z_COORD = 0xCA126C;
constexpr uintptr_t CTM_DISTANCE = 0xCA11E4;
constexpr uintptr_t CTM_ACTION_TYPE = 0xCA11F4;
constexpr uintptr_t CTM_TARGET_GUID = 0xCA11F8;

namespace
{
template <typename T>
bool writeField(MemoryManager* memory, uintptr_t address, T value)
{
    return memory && memory->writeMemory<T>(address, value);
}

bool writeCoordinates(MemoryManager* memory, std::array<float, 3> coords)
{
    return writeField(memory, CTM_X_COORD, coords[0]) && writeField(memory, CTM_Y_COORD, coords[1]) &&
           writeField(memory, CTM_Z_COORD, coords[2]);
}

void logCtmAction(CtmExecutor::ActionType action, const std::array<float, 3>& coords, float distance,
                  std::optional<quint64> guid)
{
    qCInfo(logCtm) << "CtM action" << static_cast<int>(action) << "-> (" << coords[0] << coords[1] << coords[2]
                   << ") dist:" << distance << (guid.has_value() ? QString(" guid:%1").arg(guid.value()) : "");
}
}  // namespace

CtmExecutor::CtmExecutor(MemoryManager* memory, QObject* parent) : QObject(parent), m_memory(memory) {}

CtmExecutor::~CtmExecutor() = default;

bool CtmExecutor::moveTo(float x, float y, float z, float distance)
{
    return execute(ActionType::MOVE_TO, x, y, z, distance);
}

bool CtmExecutor::attack(float x, float y, float z, quint64 guid, float distance)
{
    if (distance < 0.5f)
    {
        qCCritical(logCtm) << "Слишком маленькая дистанция для атаки!";
        return false;
    }
    return execute(ActionType::ATTACK_GUID, x, y, z, distance, guid);
}

bool CtmExecutor::loot(float x, float y, float z, quint64 guid, float distance)
{
    if (distance < 0.5f)
    {
        qCCritical(logCtm) << "Слишком маленькая дистанция для лута!";
        return false;
    }
    return execute(ActionType::LOOT, x, y, z, distance, guid);
}

bool CtmExecutor::skin(float x, float y, float z, quint64 guid, float distance)
{
    if (distance < 0.5f)
    {
        qCCritical(logCtm) << "Слишком маленькая дистанция для снятия шкуры!";
        return false;
    }
    return execute(ActionType::SKIN, x, y, z, distance, guid);
}

bool CtmExecutor::execute(ActionType action, float x, float y, float z, float distance, std::optional<quint64> guid)
{
    if (!m_memory)
    {
        qCCritical(logCtm) << "MemoryManager не инициализирован!";
        return false;
    }
    std::array<float, 3> coords = {x, y, z};
    bool ok = writeCoordinates(m_memory, coords) && writeField(m_memory, CTM_DISTANCE, distance) &&
              (!guid.has_value() || writeField(m_memory, CTM_TARGET_GUID, guid.value())) &&
              writeField(m_memory, CTM_ACTION_TYPE, static_cast<int>(action));
    if (!ok)
    {
        qCCritical(logCtm) << "Ошибка записи в память при выполнении CtM!";
        return false;
    }
    logCtmAction(action, coords, distance, guid);
    return true;
}
