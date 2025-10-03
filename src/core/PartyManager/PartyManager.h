// ФАЙЛ: src/core/PartyManager/PartyManager.h

#pragma once

#include <QObject>
#include <QMap>  // <-- ИЗМЕНЕНИЕ: Используем QMap вместо QList
#include <QLoggingCategory>
#include "Settings/PartySettings.h"          // <-- ИЗМЕНЕНИЕ: Подключаем наш новый контракт
#include "core/PartyManager/PartyContext.h"  // <-- ДОБАВИТЬ
#include <memory>                            // <-- ДОБАВИТЬ

class Bot;

Q_DECLARE_LOGGING_CATEGORY(logPartyManager)

class PartyManager : public QObject
{
    Q_OBJECT
   public:
    explicit PartyManager(QObject* parent = nullptr);
    ~PartyManager();

    void addBot(Bot* bot);
    void removeBot(Bot* bot);
    void setLeader(Bot* bot);
    Bot* leader() const;
    std::shared_ptr<PartyContext> getPartyContext() const;

    /**
     * @brief Возвращает список всех участников группы.
     * @return Список указателей на Bot.
     */
    QList<Bot*> members() const;  // <-- ИЗМЕНЕНИЕ: Сигнатура немного изменилась

    /**
     * @brief Назначает роль конкретному участнику группы.
     * @param bot Указатель на бота.
     * @param role Новая роль из перечисления PartyRole.
     * @param silent Если true, сигнал partyUpdated() не будет испущен.
     */
    void setMemberRole(Bot* bot, PartyRole role, bool silent = false);  // изменения начало и конец

    /**
     * @brief Получает настройки участника группы.
     * @param bot Указатель на бота.
     * @return Структура PartyMemberSettings.
     */
    PartyMemberSettings getMemberSettings(Bot* bot) const;

   signals:
    /**
     * @brief Сигнал, испускаемый при любом изменении в составе или настройках группы.
     * @details GUI (PartyWidget) будет подключаться к этому сигналу, чтобы автоматически
     *          обновлять отображаемую информацию (например, перерисовывать таблицу).
     */
    void partyUpdated();

   private:
    /// @brief Карта, хранящая связь "участник -> его настройки в группе".
    QMap<Bot*, PartyMemberSettings> m_members;
    std::shared_ptr<PartyContext> m_partyContext;

    /// @brief Указатель на бота, который является лидером группы.
    Bot* m_leader = nullptr;
};