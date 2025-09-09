// ФАЙЛ: src/core/Bot/Behaviors/Targeting/BlacklistTargetAction.cpp

#include "BlacklistTargetAction.h"
#include <QLoggingCategory>
#include <QDateTime>

Q_LOGGING_CATEGORY(logBlacklist, "mdbot.bt.action.blacklist")

BlacklistTargetAction::BlacklistTargetAction(int durationSeconds) : m_durationSeconds(durationSeconds) {}

/**
 * @brief Основная логика узла.
 * @details Проверяет, установлена ли цель (currentTargetGuid) в контексте.
 *          Если да, добавляет ее GUID в objectBlacklist с временем истечения.
 *          КЛЮЧЕВАЯ ОСОБЕННОСТЬ: Этот узел всегда возвращает Failure. Это используется
 *          в дереве как сигнал "цель обработана (занесена в ЧС), но продолжать
 *          взаимодействие с ней не нужно, следует перейти к другой ветке логики".
 * @param context Контекст дерева поведения.
 * @return Всегда Failure, чтобы прервать текущую ветку выполнения в дереве.
 */
NodeStatus BlacklistTargetAction::tick(BTContext& context)
{
    if (context.currentTargetGuid == 0)
    {
        qCWarning(logBlacklist) << "Cannot blacklist target: currentTargetGuid is not set.";
        return NodeStatus::Failure;
    }

    // Вычисляем время, до которого нужно игнорировать объект
    const QDateTime expirationTime = QDateTime::currentDateTime().addSecs(m_durationSeconds);

    // Добавляем или обновляем запись в черном списке
    context.objectBlacklist[context.currentTargetGuid] = expirationTime;

    qCInfo(logBlacklist) << "Object with GUID" << Qt::hex << context.currentTargetGuid << "blacklisted for"
                         << m_durationSeconds << "seconds.";

    // После добавления в ЧС, цель нужно сбросить, чтобы бот не пытался к ней двигаться
    context.currentTargetGuid = 0;

    // Возвращаем Failure, чтобы родительский Selector переключился на следующую ветку (полет по маршруту)
    return NodeStatus::Failure;
}