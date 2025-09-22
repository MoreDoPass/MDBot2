#include "IsFacingTargetCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include <cmath>  // Для cos, sin, sqrt, atan2

IsFacingTargetCondition::IsFacingTargetCondition() {}

NodeStatus IsFacingTargetCondition::tick(BTContext& context)
{
    // --- ШАГ 1: ПОЛУЧАЕМ ИСХОДНЫЕ ДАННЫЕ ---

    // Получаем GUID'ы себя и цели
    uint64_t selfGuid = context.character->getGuid();
    uint64_t targetGuid = context.currentTargetGuid;

    if (targetGuid == 0 || selfGuid == 0 || selfGuid == targetGuid)
    {
        return NodeStatus::Failure;  // Некого проверять или цель - это мы сами
    }

    // Получаем полную информацию об объектах из GOM
    const GameObjectInfo* selfInfo = context.gameObjectManager->getObjectByGuid(selfGuid);
    const GameObjectInfo* targetInfo = context.gameObjectManager->getObjectByGuid(targetGuid);

    if (!selfInfo || !targetInfo)
    {
        return NodeStatus::Failure;  // Один из объектов не найден
    }

    // --- ШАГ 2: ВЕКТОРНАЯ МАТЕМАТИКА ---

    // Вектор-стрелка "куда нужно светить" (от нас к цели)
    float dirToTargetX = targetInfo->position.x - selfInfo->position.x;
    float dirToTargetY = targetInfo->position.y - selfInfo->position.y;

    // Вектор-стрелка "куда мы светим" (из нашего orientation)
    float facingX = cos(selfInfo->orientation);
    float facingY = sin(selfInfo->orientation);

    // Нормализуем вектор на цель (делаем его "стрелкой" длиной 1)
    float length = sqrt(dirToTargetX * dirToTargetX + dirToTargetY * dirToTargetY);
    if (length > 0)
    {  // Защита от деления на ноль, если мы стоим в той же точке
        dirToTargetX /= length;
        dirToTargetY /= length;
    }

    // --- ШАГ 3: СКАЛЯРНОЕ ПРОИЗВЕДЕНИЕ И ПРОВЕРКА ---

    // Вычисляем, насколько "хорошо" мы смотрим на цель
    float dotProduct = (facingX * dirToTargetX) + (facingY * dirToTargetY);

    // Мы используем порог 0.707f, который соответствует "конусу" примерно в ±45 градусов.
    // Это значение обеспечивает естественное поведение, не требуя идеального роботизированного прицеливания.
    const float HUMANIZER_ACCURACY_THRESHOLD = 0.707f;

    if (dotProduct >= HUMANIZER_ACCURACY_THRESHOLD)
    {
        return NodeStatus::Success;  // Мы смотрим на цель
    }

    return NodeStatus::Failure;  // Мы НЕ смотрим на цель
}