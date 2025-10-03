#pragma once
#include <QMetaType>
/**
 * @brief Определяет возможные роли участника группы.
 */
enum class PartyRole
{
    Unassigned,  ///< Роль не назначена
    Tank,        ///< Танк
    Healer,      ///< Лекарь
    Damage       ///< Боец (наносящий урон)
};

Q_DECLARE_METATYPE(PartyRole)

/**
 * @brief Хранит специфичные для группы настройки одного участника.
 * @details Эта структура не принадлежит самому боту, а хранится в PartyManager.
 *          Она определяет, как бот должен вести себя ИМЕННО в этой группе.
 */
struct PartyMemberSettings
{
    /// @brief Текущая роль участника в группе.
    PartyRole role = PartyRole::Unassigned;

    // Сюда в будущем мы будем добавлять другие настройки, например:
    // int auraIdToUse = 0;
    // int blessingIdToUse = 0;
    // bool shouldPull = false;
};