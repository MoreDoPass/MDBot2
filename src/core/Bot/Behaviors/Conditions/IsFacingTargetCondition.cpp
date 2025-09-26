#include "IsFacingTargetCondition.h"
#include "core/BehaviorTree/BTContext.h"
#include <cmath>  // Для cos, sin, sqrt, atan2

IsFacingTargetCondition::IsFacingTargetCondition() {}

NodeStatus IsFacingTargetCondition::tick(BTContext& context)
{
    // --- ШАГ 1: ПОЛУЧАЕМ ИСХОДНЫЕ ДАННЫЕ ---

    uint64_t targetGuid = context.currentTargetGuid;
    if (targetGuid == 0)
    {
        return NodeStatus::Failure;  // Нет цели - не на кого смотреть
    }

    // === НОВАЯ, ПРАВИЛЬНАЯ ЛОГИКА ===
    // 1. Получаем данные о нашем персонаже НАПРЯМУЮ из Character
    const Vector3 selfPosition = context.character->getPosition();
    const float selfOrientation = context.character->getOrientation();

    // 2. Получаем данные о цели из GameObjectManager
    const GameObjectInfo* targetInfo = context.gameObjectManager->getObjectByGuid(targetGuid);

    if (!targetInfo)
    {
        return NodeStatus::Failure;  // Цель исчезла
    }

    // --- ШАГ 2: ВЕКТОРНАЯ МАТЕМАТИКА (остается без изменений) ---

    // Вектор-стрелка "куда нужно светить" (от нас к цели)
    float dirToTargetX = targetInfo->position.x - selfPosition.x;
    float dirToTargetY = targetInfo->position.y - selfPosition.y;

    // Вектор-стрелка "куда мы светим" (из нашего orientation)
    float facingX = cos(selfOrientation);
    float facingY = sin(selfOrientation);

    // Нормализуем вектор на цель (делаем его "стрелкой" длиной 1)
    float length = sqrt(dirToTargetX * dirToTargetX + dirToTargetY * dirToTargetY);
    if (length > 0)
    {
        dirToTargetX /= length;
        dirToTargetY /= length;
    }

    // --- ШАГ 3: СКАЛЯРНОЕ ПРОИЗВЕДЕНИЕ И ПРОВЕРКА (остается без изменений) ---

    // Вычисляем, насколько "хорошо" мы смотрим на цель
    float dotProduct = (facingX * dirToTargetX) + (facingY * dirToTargetY);

    const float HUMANIZER_ACCURACY_THRESHOLD = 0.707f;

    if (dotProduct >= HUMANIZER_ACCURACY_THRESHOLD)
    {
        return NodeStatus::Success;  // Мы смотрим на цель
    }

    return NodeStatus::Failure;  // Мы НЕ смотрим на цель
}