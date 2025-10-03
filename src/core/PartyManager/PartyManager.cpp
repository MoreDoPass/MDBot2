// ФАЙЛ: src/core/PartyManager/PartyManager.cpp

#include "PartyManager.h"
#include "core/Bot/Bot.h"

Q_LOGGING_CATEGORY(logPartyManager, "core.partymanager")

PartyManager::PartyManager(QObject* parent) : QObject(parent)
{
    m_partyContext = std::make_shared<PartyContext>();
    qCInfo(logPartyManager) << "PartyManager created.";
}

PartyManager::~PartyManager()
{
    qCInfo(logPartyManager) << "PartyManager destroyed.";
}

void PartyManager::addBot(Bot* bot)
{
    if (!bot || m_members.contains(bot)) return;

    // Добавляем бота в карту с настройками по умолчанию
    m_members.insert(bot, {});  // {} создает PartyMemberSettings()
    qCInfo(logPartyManager) << "Bot with PID" << bot->processId()
                            << "added to the party. Total members:" << m_members.size();

    // Сообщаем всем, что группа изменилась
    emit partyUpdated();
}

void PartyManager::removeBot(Bot* bot)
{
    if (!bot) return;

    if (m_members.remove(bot) > 0)
    {
        qCInfo(logPartyManager) << "Bot with PID" << bot->processId()
                                << "removed from the party. Total members:" << m_members.size();
        if (m_leader == bot)
        {
            m_leader = nullptr;
            qCInfo(logPartyManager) << "The removed bot was the leader. Leader is now unassigned.";
        }
        emit partyUpdated();
    }
}

void PartyManager::setLeader(Bot* bot)
{
    if (!bot)
    {
        m_leader = nullptr;
        qCInfo(logPartyManager) << "Leader has been unassigned.";
        emit partyUpdated();
        return;
    }

    if (!m_members.contains(bot))
    {
        qCWarning(logPartyManager) << "Attempted to set a non-member bot as a leader. PID:" << bot->processId();
        return;
    }

    m_leader = bot;
    qCInfo(logPartyManager) << "Bot with PID" << bot->processId() << "is now the party leader.";
    emit partyUpdated();
}

Bot* PartyManager::leader() const
{
    return m_leader;
}

// Возвращаем список ключей из нашей карты - это и есть все участники
QList<Bot*> PartyManager::members() const
{
    return m_members.keys();
}

void PartyManager::setMemberRole(Bot* bot, PartyRole role, bool silent)  // изменения начало
{
    // Проверяем, существует ли бот и действительно ли роль изменилась
    if (m_members.contains(bot) && m_members[bot].role != role)
    {
        m_members[bot].role = role;
        qCInfo(logPartyManager) << "Role for bot" << bot->processId() << "set to" << static_cast<int>(role);
        // Испускаем сигнал только если были реальные изменения и если нас не просили быть "тихими"
        if (!silent)  // изменения начало
        {
            emit partyUpdated();
        }  // изменения конец
    }
}

PartyMemberSettings PartyManager::getMemberSettings(Bot* bot) const
{
    // Возвращаем настройки или пустую структуру, если бот не найден
    return m_members.value(bot, {});
}

std::shared_ptr<PartyContext> PartyManager::getPartyContext() const
{
    return m_partyContext;
}