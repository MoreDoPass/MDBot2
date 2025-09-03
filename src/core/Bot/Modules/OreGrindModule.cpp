#include "OreGrindModule.h"
#include "core/BehaviorTree/SequenceNode.h"
// Подключаем наш новый, правильный "навык"
#include "core/Bot/Behaviors/Targeting/FindGameObjectByTypeAction.h"
#include "core/Bot/Behaviors/Movement/MoveToTargetAction.h"

std::unique_ptr<BTNode> OreGrindModule::build()
{
    // --- ВОТ ОНО, ИСПРАВЛЕНИЕ ---
    // 1. Создаем пустой вектор, который будет хранить наши "навыки".
    std::vector<std::unique_ptr<BTNode>> children;

    // 2. Создаем "навык" и ПЕРЕМЕЩАЕМ (std::move) его в вектор.
    //    Мы говорим: "Ищи объекты типа GameObject (руда, трава)".
    children.push_back(std::make_unique<FindGameObjectByTypeAction>(GameObjectType::GameObject));

    // Шаг 2: Двигаться к найденной цели.
    children.push_back(std::make_unique<MoveToTargetAction>());

    // 3. Создаем узел SequenceNode и ПЕРЕМЕЩАЕМ (std::move) в него весь наш вектор.
    return std::make_unique<SequenceNode>(std::move(children));
}