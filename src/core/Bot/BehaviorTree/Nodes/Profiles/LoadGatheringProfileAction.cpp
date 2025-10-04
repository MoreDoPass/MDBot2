#include "LoadGatheringProfileAction.h"
#include "core/ProfileManager/ProfileManager.h"  // Нам нужен доступ к менеджеру
#include "core/Bot/Settings/BotSettings.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logLoadProfile, "mdbot.bt.action.loadprofile")

NodeStatus LoadGatheringProfileAction::tick(BTContext& context)
{
    const QString& currentProfilePath = context.settings.gatheringSettings.profilePath;

    // 1. Проверяем, нужно ли загружать профиль.
    // Если профиль уже загружен И путь к файлу профиля не изменился, то просто возвращаем успех.
    if (context.gatheringProfile && context.gatheringProfile->sourceFilePath == currentProfilePath)
    {
        qCDebug(logLoadProfile) << "Profile already loaded and path unchanged:" << currentProfilePath;
        return NodeStatus::Success;
    }

    // Если профиль загружен, но путь изменился, или профиля нет, то мы продолжаем загрузку.

    if (!context.profileManager)
    {
        qCCritical(logLoadProfile) << "ProfileManager is null in BTContext! Cannot load profile.";
        return NodeStatus::Failure;
    }

    if (currentProfilePath.isEmpty())
    {
        qCCritical(logLoadProfile) << "Profile path is empty in settings. Cannot load profile.";
        context.gatheringProfile.reset();  // Очищаем старый профиль, если путь стал пустым.
        return NodeStatus::Failure;
    }

    qCInfo(logLoadProfile) << "Loading gathering profile from:" << currentProfilePath;
    context.gatheringProfile = context.profileManager->getGatheringProfile(currentProfilePath);

    if (context.gatheringProfile)
    {
        // После успешной загрузки, ProfileManager уже сохранил sourceFilePath внутри профиля.

        qCInfo(logLoadProfile) << "Profile" << context.gatheringProfile->profileName
                               << "loaded successfully from file:" << context.gatheringProfile->sourceFilePath << "with"
                               << context.gatheringProfile->path.size() << "waypoints and"
                               << context.gatheringProfile->nodeIdsToGather.size() << "node IDs.";

        if (!context.gatheringProfile->nodeIdsToGather.empty())
        {
            qCInfo(logLoadProfile) << "Overwriting gathering node IDs from profile.";
            context.settings.gatheringSettings.nodeIdsToGather = context.gatheringProfile->nodeIdsToGather;
        }
        else
        {
            qCWarning(logLoadProfile) << "Profile does not contain 'gatherNodeIds', using settings from GUI.";
        }
        return NodeStatus::Success;
    }

    qCCritical(logLoadProfile) << "Failed to load or parse profile from path:" << currentProfilePath;
    context.gatheringProfile.reset();
    return NodeStatus::Failure;
}