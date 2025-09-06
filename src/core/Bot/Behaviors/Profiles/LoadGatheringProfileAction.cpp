#include "LoadGatheringProfileAction.h"
#include "core/ProfileManager/ProfileManager.h"  // Нам нужен доступ к менеджеру
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logLoadProfile, "mdbot.bt.action.loadprofile")

NodeStatus LoadGatheringProfileAction::tick(BTContext& context)
{
    // Этот узел должен сработать только один раз.
    // Если профиль уже загружен в контекст, просто возвращаем успех.
    if (context.gatheringProfile)
    {
        return NodeStatus::Success;
    }

    // Проверяем, что ProfileManager доступен
    if (!context.profileManager)
    {
        qCCritical(logLoadProfile) << "ProfileManager is null in BTContext! Cannot load profile.";
        return NodeStatus::Failure;
    }

    // Получаем путь к файлу из настроек, которые хранятся в контексте
    const QString& path = context.settings.gatheringSettings.profilePath;
    if (path.isEmpty())
    {
        qCCritical(logLoadProfile) << "Profile path is empty in settings. Cannot load profile.";
        return NodeStatus::Failure;
    }

    qCInfo(logLoadProfile) << "Loading gathering profile from:" << path;
    // Обращаемся к менеджеру и просим загрузить профиль.
    // Результат (умный указатель) сохраняем в контекст для других узлов.
    context.gatheringProfile = context.profileManager->getGatheringProfile(path);

    if (context.gatheringProfile)
    {
        qCInfo(logLoadProfile) << "Profile loaded successfully.";
        // Важно: После загрузки обновляем ID для поиска, взяв их из профиля!
        context.settings.gatheringSettings.nodeIdsToGather = context.gatheringProfile->nodeIdsToGather;
        return NodeStatus::Success;
    }

    qCCritical(logLoadProfile) << "Failed to load or parse profile from path:" << path;
    return NodeStatus::Failure;
}