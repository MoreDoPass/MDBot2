#include "ProfileManager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logProfileManager, "mdbot.profilemanager")

ProfileManager::ProfileManager(QObject* parent) : QObject(parent)
{
    qCInfo(logProfileManager) << "ProfileManager created.";
}

ProfileManager::~ProfileManager()
{
    qCInfo(logProfileManager) << "ProfileManager destroyed.";
}

std::shared_ptr<GatheringProfile> ProfileManager::getGatheringProfile(const QString& path)
{
    // Потокобезопасная блокировка
    QMutexLocker locker(&m_mutex);

    // 1. Проверяем кэш
    if (m_loadedProfiles.contains(path))
    {
        qCDebug(logProfileManager) << "Returning cached profile for path:" << path;
        return m_loadedProfiles.value(path);
    }

    qCInfo(logProfileManager) << "Cache miss. Loading profile from path:" << path;
    // 2. Если в кэше нет - парсим файл
    auto newProfile = parseGatheringProfile(path);

    if (newProfile)
    {
        // 3. Если парсинг успешен, сохраняем в кэш
        m_loadedProfiles.insert(path, newProfile);
        qCInfo(logProfileManager) << "Profile loaded and cached successfully.";
    }

    return newProfile;
}

// Этот метод мы полностью переписываем, чтобы он читал твой формат
std::shared_ptr<GatheringProfile> ProfileManager::parseGatheringProfile(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
    {
        qCCritical(logProfileManager) << "Failed to open profile file:" << path << "Error:" << file.errorString();
        return nullptr;
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (doc.isNull() || !doc.isObject())
    {
        qCCritical(logProfileManager) << "Failed to parse JSON from file, or it's not a JSON object:" << path;
        return nullptr;
    }

    QJsonObject root = doc.object();

    // Проверяем тип профиля. Это обязательно.
    if (root.value("profileType").toString() != "Gathering")
    {
        qCCritical(logProfileManager) << "Invalid profile type. Expected 'Gathering', but got:"
                                      << root.value("profileType").toString();
        return nullptr;
    }

    // Создаем наш объект профиля
    auto profile = std::make_shared<GatheringProfile>();
    profile->sourceFilePath = path;

    // --- НЕОБЯЗАТЕЛЬНЫЕ ПОЛЯ (для расширенного формата) ---
    // Парсер не будет ругаться, если этих полей нет.

    // Имя профиля
    if (root.contains("profileName"))
    {
        profile->profileName = root.value("profileName").toString("Unnamed Profile");
    }

    // Настройки
    if (root.contains("settings") && root.value("settings").isObject())
    {
        QJsonObject settingsObj = root.value("settings").toObject();
        QString startLogicStr = settingsObj.value("startPointLogic").toString("FromTheNearest");
        if (startLogicStr == "FromTheFirst")
        {
            profile->startLogic = GatheringProfile::StartPointLogic::FromTheFirst;
        }
        else
        {
            profile->startLogic = GatheringProfile::StartPointLogic::FromTheNearest;
        }
    }

    // ID ресурсов
    if (root.contains("gatherNodeIds") && root.value("gatherNodeIds").isArray())
    {
        for (const auto& val : root.value("gatherNodeIds").toArray())
        {
            profile->nodeIdsToGather.push_back(val.toInt());
        }
    }

    // --- ОБЯЗАТЕЛЬНОЕ ПОЛЕ (для твоего простого формата) ---
    // Маршрут
    if (root.contains("path") && root.value("path").isArray())
    {
        for (const auto& val : root.value("path").toArray())
        {
            QJsonObject pointObj = val.toObject();
            // Проверяем, что в точке есть все координаты
            if (pointObj.contains("X") && pointObj.contains("Y") && pointObj.contains("Z"))
            {
                profile->path.push_back({static_cast<float>(pointObj.value("X").toDouble()),
                                         static_cast<float>(pointObj.value("Y").toDouble()),
                                         static_cast<float>(pointObj.value("Z").toDouble())});
            }
        }
    }

    // Проверяем, что мы загрузили хоть что-то полезное
    if (profile->path.empty())
    {
        qCWarning(logProfileManager) << "Profile" << path << "was loaded, but it contains no path points.";
    }

    qCInfo(logProfileManager) << "Parsed profile:" << profile->profileName << "with" << profile->path.size()
                              << "waypoints and" << profile->nodeIdsToGather.size() << "node IDs.";

    return profile;
}

std::shared_ptr<GrindingProfile> ProfileManager::getGrindingProfile(const QString& path)
{
    QMutexLocker locker(&m_mutex);

    if (m_grindingProfileCache.contains(path))
    {
        qCDebug(logProfileManager) << "Returning cached grinding profile for path:" << path;
        return m_grindingProfileCache.value(path);
    }

    qCInfo(logProfileManager) << "Cache miss. Loading grinding profile from path:" << path;
    auto newProfile = parseGrindingProfile(path);

    if (newProfile)
    {
        m_grindingProfileCache.insert(path, newProfile);
        qCInfo(logProfileManager) << "Grinding profile loaded and cached successfully.";
    }

    return newProfile;
}

// parseGrindingProfile - парсер, заточенный под наш новый формат
std::shared_ptr<GrindingProfile> ProfileManager::parseGrindingProfile(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
    {
        qCCritical(logProfileManager) << "Failed to open profile file:" << path << "Error:" << file.errorString();
        return nullptr;
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (doc.isNull() || !doc.isObject())
    {
        qCCritical(logProfileManager) << "Failed to parse JSON from file, or it's not a JSON object:" << path;
        return nullptr;
    }

    QJsonObject root = doc.object();

    // 1. Проверяем тип профиля. Теперь мы ищем "Grinding".
    if (root.value("profileType").toString() != "Grinding")
    {
        qCCritical(logProfileManager) << "Invalid profile type. Expected 'Grinding', but got:"
                                      << root.value("profileType").toString();
        return nullptr;
    }

    // 2. Создаем наш объект профиля гринда
    auto profile = std::make_shared<GrindingProfile>();

    // 3. Парсим имя (необязательно)
    profile->profileName = root.value("profileName").toString("Unnamed Grinding Profile");

    // 4. Парсим ID мобов (ключевая часть)
    if (root.contains("mobIds") && root.value("mobIds").isArray())
    {
        for (const auto& val : root.value("mobIds").toArray())
        {
            profile->mobIdsToGrind.push_back(val.toInt());
        }
    }

    // 5. Парсим маршрут (общая часть для всех профилей)
    if (root.contains("path") && root.value("path").isArray())
    {
        for (const auto& val : root.value("path").toArray())
        {
            QJsonObject pointObj = val.toObject();
            if (pointObj.contains("X") && pointObj.contains("Y") && pointObj.contains("Z"))
            {
                profile->path.push_back({static_cast<float>(pointObj.value("X").toDouble()),
                                         static_cast<float>(pointObj.value("Y").toDouble()),
                                         static_cast<float>(pointObj.value("Z").toDouble())});
            }
        }
    }

    qCInfo(logProfileManager) << "Parsed grinding profile:" << profile->profileName << "with" << profile->path.size()
                              << "waypoints and" << profile->mobIdsToGrind.size() << "mob IDs.";

    return profile;
}