// ФАЙЛ: src/core/Bot/Behaviors/Movement/ModifyTargetZAction.cpp

#include "ModifyTargetZAction.h"
#include <QLoggingCategory>

// Создаем отдельную категорию логов для этого узла
Q_LOGGING_CATEGORY(logModifyZ, "mdbot.bt.action.modifyz")

/**
 * @brief Конструктор. Просто сохраняет смещение для последующего использования.
 * @param zOffset Смещение по оси Z.
 */
ModifyTargetZAction::ModifyTargetZAction(float zOffset) : m_zOffset(zOffset) {}

/**
 * @brief Основная логика.
 * @details Проверяет, что в контексте установлена цель-позиция, и если да,
 *          прибавляет к ее Z-координате сохраненное смещение.
 */
NodeStatus ModifyTargetZAction::tick(BTContext& context)
{
    // 1. Проверка безопасности: есть ли вообще цель, которую можно менять?
    //    Если x, y и z равны нулю, скорее всего, цель не была установлена.
    if (context.currentTargetPosition.x == 0 && context.currentTargetPosition.y == 0 &&
        context.currentTargetPosition.z == 0)
    {
        qCWarning(logModifyZ) << "Cannot modify Z coordinate: currentTargetPosition is not set.";
        return NodeStatus::Failure;  // Провал, делать нечего.
    }

    // 2. Логирование для отладки (очень полезно)
    qCDebug(logModifyZ) << "Modifying target Z from" << context.currentTargetPosition.z << "to"
                        << (context.currentTargetPosition.z + m_zOffset);

    // 3. Главное действие: изменяем координату в общем контексте.
    context.currentTargetPosition.z += m_zOffset;

    // 4. Возвращаем результат.
    //    Эта операция мгновенная и не может провалиться (если прошла проверку).
    //    Поэтому всегда возвращаем Success.
    return NodeStatus::Success;
}