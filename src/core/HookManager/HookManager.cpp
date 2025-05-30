#include "HookManager.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(hookManagerLog, "core.hookmanager")

HookManager::HookManager(QObject* parent) : QObject(parent), m_memoryManager(nullptr)
{
    qCInfo(hookManagerLog) << "HookManager создан";
}

HookManager::HookManager(MemoryManager* memoryManager) : QObject(nullptr), m_memoryManager(memoryManager)
{
    qCInfo(hookManagerLog) << "HookManager создан с MemoryManager";
}

HookManager::~HookManager()
{
    clearAllHooks();
    qCInfo(hookManagerLog) << "HookManager уничтожен";
}

bool HookManager::addHook(uintptr_t address, void* callback, int hookType)
{
    QMutexLocker locker(&m_mutex);
    if (m_hooks.contains(address))
    {
        qCWarning(hookManagerLog) << "Хук уже установлен на адрес" << Qt::hex << address;
        return false;
    }
    // TODO: Реализация установки хука
    // Здесь должна быть работа с MemoryManager и сохранение оригинальных байт
    HookInfo info;
    info.callback = callback;
    info.hookType = hookType;
    // info.originalBytes = ...
    m_hooks.insert(address, info);
    qCInfo(hookManagerLog) << "Хук установлен на адрес" << Qt::hex << address;
    return true;
}

bool HookManager::removeHook(uintptr_t address)
{
    QMutexLocker locker(&m_mutex);
    if (!m_hooks.contains(address))
    {
        qCWarning(hookManagerLog) << "Нет хука на адресе" << Qt::hex << address;
        return false;
    }
    // TODO: Реализация снятия хука и восстановление оригинальных байт
    m_hooks.remove(address);
    qCInfo(hookManagerLog) << "Хук снят с адреса" << Qt::hex << address;
    return true;
}

bool HookManager::isHooked(uintptr_t address) const
{
    QMutexLocker locker(&m_mutex);
    return m_hooks.contains(address);
}

QByteArray HookManager::getOriginalBytes(uintptr_t address) const
{
    QMutexLocker locker(&m_mutex);
    if (!m_hooks.contains(address)) return QByteArray();
    return m_hooks.value(address).originalBytes;
}

bool HookManager::clearAllHooks()
{
    QMutexLocker locker(&m_mutex);
    bool allOk = true;
    for (auto it = m_hooks.begin(); it != m_hooks.end();)
    {
        // TODO: Реализация снятия хука
        qCInfo(hookManagerLog) << "Снимаем хук с адреса" << Qt::hex << it.key();
        it = m_hooks.erase(it);
    }
    return allOk;
}
