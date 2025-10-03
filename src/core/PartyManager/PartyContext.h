#pragma once
#include "Shared/Utils/Vector.h"
#include <cstdint>

// Возможные "приказы дня" для всей группы.
// Пока что их будет всего два.
enum class PartyTask
{
    None,         // Ничего не делать (когда группа уже собрана и готова)
    FormingGroup  // Приказ: "Собираем группу!"
};

// Сама "доска объявлений". Простая структура.
struct PartyContext
{
    // Какой "приказ" висит на доске прямо сейчас?
    PartyTask currentTask = PartyTask::None;

    // Эти поля нам понадобятся в будущем для приказов "Идти в точку Х"
    // или "Атаковать цель Y". Пока просто держим их здесь.
    Vector3 targetPosition;
    uint64_t targetGuid = 0;
};