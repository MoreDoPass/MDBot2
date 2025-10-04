#include "ModuleBuilder.h"
#include "core/BehaviorTree/BTContext.h"
#include "core/Bot/Settings/BotSettings.h"
#include <QLoggingCategory>

// Подключаем все модули, о которых должен знать этот строитель
#include "core/Bot/BehaviorTree/Modules/Gathering/OreGrindModule.h"
#include "core/Bot/BehaviorTree/Modules/Grinding/MobGrindModule.h"

// Создаем собственную категорию логирования для удобной отладки
Q_LOGGING_CATEGORY(logModuleBuilder, "mdbot.bot.bt.modulebuilder")

std::unique_ptr<BTNode> ModuleBuilder::build(BTContext& context, std::unique_ptr<BTNode> combatBehavior)
{
    const ModuleType activeModule = context.settings.activeModule;
    qCInfo(logModuleBuilder) << "Building main module for type:" << static_cast<int>(activeModule);

    // --- ЭТОТ БЛОК ПЕРЕЕХАЛ ИЗ Bot::start() ---
    switch (activeModule)
    {
        case ModuleType::Gathering:
            // Просто возвращаем результат сборки нужного модуля,
            // передавая ему боевую логику "по наследству".
            return OreGrindModule::build(context, std::move(combatBehavior));

        case ModuleType::Grinding:
            return MobGrindModule::build(context, std::move(combatBehavior));

            // В БУДУЩЕМ МЫ БУДЕМ ДОБАВЛЯТЬ НОВЫЕ МОДУЛИ СЮДА:
            // case ModuleType::Questing:
            //     return QuestingModule::build(context, std::move(combatBehavior));

        default:
            qCCritical(logModuleBuilder) << "Attempted to build with an unknown or unsupported module type:"
                                         << static_cast<int>(activeModule);
            // Возвращаем nullptr, чтобы бот не запустился с некорректным деревом.
            // unique_ptr на combatBehavior будет здесь автоматически уничтожен, утечки не будет.
            return nullptr;
    }
}