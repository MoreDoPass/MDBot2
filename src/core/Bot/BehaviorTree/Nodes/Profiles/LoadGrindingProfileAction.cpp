// --- НАЧАЛО ФАЙЛА core/Bot/BehaviorTree/Nodes/Profiles/LoadGrindingProfileAction.cpp ---
#include "LoadGrindingProfileAction.h"
#include "core/ProfileManager/ProfileManager.h"
#include "core/BehaviorTree/BTContext.h"  // Убедимся, что полный контекст подключен
#include <QLoggingCategory>

// Создаем новую, отдельную категорию логирования для ясности
Q_LOGGING_CATEGORY(logLoadGrindProfile, "mdbot.bt.action.loadgrindprofile")

NodeStatus LoadGrindingProfileAction::tick(BTContext& context)
{
    try
    {
        // Этот узел должен сработать успешно только один раз.
        // Если профиль гринда уже загружен в контекст, просто возвращаем успех.
        if (context.grindingProfile)
        {
            return NodeStatus::Success;
        }

        // Проверяем, что ProfileManager доступен в контексте
        if (!context.profileManager)
        {
            qCCritical(logLoadGrindProfile) << "ProfileManager is null in BTContext! Cannot load profile.";
            return NodeStatus::Failure;
        }

        // Получаем путь к файлу из настроек гринда, которые хранятся в контексте
        const QString& path = context.settings.grindingSettings.profilePath;
        if (path.isEmpty())
        {
            qCCritical(logLoadGrindProfile) << "Grinding profile path is empty in settings. Cannot load profile.";
            return NodeStatus::Failure;
        }

        qCInfo(logLoadGrindProfile) << "Loading grinding profile from:" << path;

        // Обращаемся к менеджеру и просим загрузить профиль гринда.
        // Результат (умный указатель) сохраняем в поле контекста, предназначенное для гринда.
        context.grindingProfile = context.profileManager->getGrindingProfile(path);

        // Проверяем, удалось ли загрузить и распарсить профиль
        if (context.grindingProfile)
        {
            qCInfo(logLoadGrindProfile) << "Profile" << context.grindingProfile->profileName
                                        << "loaded successfully with" << context.grindingProfile->path.size()
                                        << "waypoints.";

            // --- ЛОГИКА ПЕРЕЗАПИСИ НАСТРОЕК ИЗ ПРОФИЛЯ ---
            // Если в самом JSON-файле профиля указаны ID мобов, они имеют приоритет
            // над тем, что пользователь ввел в GUI.
            if (!context.grindingProfile->mobIdsToGrind.empty())
            {
                qCInfo(logLoadGrindProfile)
                    << "Overwriting NPC IDs from profile. Count:" << context.grindingProfile->mobIdsToGrind.size();
                // Мы перезаписываем список ID в настройках, чтобы другие узлы могли его использовать
                context.settings.grindingSettings.npcIdsToGrind = context.grindingProfile->mobIdsToGrind;
            }

            return NodeStatus::Success;
        }
        else
        {
            qCCritical(logLoadGrindProfile) << "Failed to load or parse grinding profile from path:" << path;
            return NodeStatus::Failure;
        }
    }
    catch (const std::exception& e)
    {
        qCCritical(logLoadGrindProfile) << "An exception occurred while loading grinding profile:" << e.what();
        return NodeStatus::Failure;
    }
}
// --- КОНЕЦ ФАЙЛА core/Bot/BehaviorTree/Nodes/Profiles/LoadGrindingProfileAction.cpp ---