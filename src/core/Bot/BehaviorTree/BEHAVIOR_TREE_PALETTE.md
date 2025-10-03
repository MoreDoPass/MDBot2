Framework:
NodeStatus: Success, Failure, Running
Composites:
SequenceNode(children) -> "И" (AND)
SelectorNode(children) -> "ИЛИ" (OR)
Decorators:
InverterNode(child) -> "НЕ" (NOT)
WhileSuccessDecorator(child) -> Цикл, пока Success. Завершается на Failure.
RunWhileConditionDecorator(child, conditionFunc) -> "Захват" выполнения, пока лямбда true.

Behaviors
Enums:
UnitSource: Self, CurrentTarget
ComparisonType: GreaterOrEqual, Less, Equal, Greater, LessOrEqual
HealthCheckType: Percentage, Absolute, Missing
Nodes:
Проверки Состояния (Conditions)
[C] HasTargetCondition(GameObjectType) -> Проверяет, есть ли цель (currentTargetGuid) и ее тип. # "Targeting/HasTargetCondition.h"
[C] HasBuffCondition(UnitSource, int, bool) -> Проверяет наличие/отсутствие ауры. # "Conditions/HasBuffCondition.h"
[C] IsInCombatCondition(UnitSource, bool) -> Проверяет, в бою ли юнит. # "Conditions/IsInCombatCondition.h"
[C] IsAutoAttackingCondition(UnitSource, bool) -> Проверяет, активна ли автоатака. # "Combat/IsAutoAttackingCondition.h"
[C] IsCastingCondition(UnitSource, int, bool) -> Проверяет, кастует ли юнит (опционально - конкретный спелл). # "Combat/IsCastingCondition.h"
[C] IsFacingTargetCondition() -> Проверяет, смотрит ли персонаж на цель. # "Movement/IsFacingTargetCondition.h"
[C] IsHealthCondition(UnitSource, ComparisonType, HealthCheckType, float) -> Проверяет здоровье (%, абс., недостающее). # "Conditions/IsHealthCondition.h"
[C] IsInRangeCondition(float) -> Проверяет, находится ли персонаж в радиусе от цели. # "Movement/IsInRangeCondition.h"
[C] IsLevelCondition(UnitSource, ComparisonType, int) -> Сравнивает уровень юнита. # "Conditions/IsLevelCondition.h"
[C] IsPlayersNearbyCondition(float) -> Проверяет, есть ли другие игроки рядом. # "Conditions/IsPlayersNearbyCondition.h"
[C] IsSpellOnCooldownCondition(int) -> Проверяет КД заклинания + ГКД (успех, если КД нет). # "Combat/IsSpellOnCooldownCondition.h"
Поиск Целей (Targeting)
[A] FindAggressorAction() -> context.currentTargetGuid = атакующий нас юнит. # "Targeting/FindAggressorAction.h"
[A] FindGameObjectByTypeAction(GameObjectType) -> Находит ближайший объект по типу, пишет в currentTargetGuid. # "Targeting/FindGameObjectByTypeAction.h"
[A] FindObjectByIdAction(vector<int>) -> Находит ближайший объект из списка ID, пишет в currentTargetGuid. # "Targeting/FindObjectByIdAction.h"
Действия в Бою (Combat)
[A] CastSpellAction(UnitSource, int) -> Кастует заклинание. Возвращает Running. # "Combat/CastSpellAction.h"
[A] StartAutoAttackAction() -> Включает автоатаку по currentTargetGuid. # "Combat/StartAutoAttackAction.h"
Передвижение (Movement)
[A] FaceTargetAction() -> Поворачивается лицом к currentTargetGuid. # "Movement/FaceTargetAction.h"
[A] FollowPathAction() -> Управляет движением по маршруту из профиля, пишет в currentTargetPosition. # "Movement/FollowPathAction.h"
[A] MoveToTargetAction() -> Движется к currentTargetGuid или currentTargetPosition. Возвращает Running. # "Movement/MoveToTargetAction.h"
[A] TeleportToTargetAction(float) -> Телепортируется к цели (с опциональным отступом). # "Movement/TeleportToTargetAction.h"
[A] ModifyTargetZAction(float) -> Изменяет Z-координату у currentTargetPosition. # "Movement/ModifyTargetZAction.h"
Взаимодействие (Interaction)
[A] InteractWithTargetAction() -> Выполняет "правый клик" по currentTargetGuid (сбор, лут). # "Interaction/InteractWithTargetAction.h"
Утилиты (Utility)
[A] BlacklistTargetAction(int) -> Добавляет currentTargetGuid во временный ЧС. Всегда Failure. # "Targeting/BlacklistTargetAction.h"
[A] ClearTargetAction() -> Обнуляет context.currentTargetGuid. # "Targeting/ClearTargetAction.h"
[A] LoadGatheringProfileAction() -> Загружает профиль из настроек в context.gatheringProfile. # "Profile/LoadGatheringProfileAction.h"
[A] WaitAction(float) -> Ждет указанное кол-во миллисекунд. Возвращает Running. # "Utility/WaitAction.h"
[A] FailNode() -> Ничего не делает. Всегда Failure. # "Utility/FailNode.h"
