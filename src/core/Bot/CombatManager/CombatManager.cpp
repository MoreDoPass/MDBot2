// Файл: src/core/bot/CombatManager/CombatManager.cpp
#include "CombatManager.h"
#include "Shared/Data/SharedData.h"  // Нам нужен доступ к структурам из общей памяти
#include <QLoggingCategory>

// Создаем категорию логов для удобной отладки
Q_LOGGING_CATEGORY(logCombatManager, "mdbot.combatmanager")

CombatManager::CombatManager(SharedMemoryManager* sharedMemory, QObject* parent)
    : QObject(parent), m_sharedMemory(sharedMemory)
{
    if (!m_sharedMemory)
    {
        // Критическая ошибка, если нам не передали общую память
        qFatal("CombatManager created with a null SharedMemoryManager!");
    }
    qCInfo(logCombatManager) << "CombatManager created.";
}

bool CombatManager::castSpellOnTarget(int spellId, uint64_t targetGUID)
{
    if (!m_sharedMemory) return false;

    // Получаем прямой доступ к общей памяти
    SharedData* data = m_sharedMemory->getMemoryPtr();
    if (!data)
    {
        qCCritical(logCombatManager) << "Cannot cast spell: Failed to get pointer to shared memory.";
        return false;
    }

    // --- ЛОГИКА ОТПРАВКИ КОМАНДЫ ---

    // 1. Проверяем, свободен ли "агент" (DLL).
    // Если он еще выполняет старую команду, новую не отправляем.
    if (data->commandToDll.status != CommandStatus::None)
    {
        qCWarning(logCombatManager) << "Cannot cast spell: DLL is busy with another command.";
        return false;
    }

    // 2. Заполняем "бланк заказа" данными, которые нам передали
    data->commandToDll.type = ClientCommandType::CastSpellOnTarget;
    data->commandToDll.spellId = spellId;
    data->commandToDll.targetGuid = targetGUID;
    data->commandToDll.status = CommandStatus::Pending;

    qCInfo(logCombatManager) << "CastSpellOnTarget command sent. SpellID:" << spellId << "TargetGUID:" << Qt::hex
                             << targetGUID;

    return true;
}