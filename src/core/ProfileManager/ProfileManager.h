#pragma once

#include "core/Bot/BehaviorTree/Profiles/GatheringProfile.h"  // Подключаем наш "чертеж"
#include "core/Bot/BehaviorTree/Profiles/GrindingProfile.h"
#include <QObject>
#include <QMap>
#include <QMutex>
#include <memory>  // для std::shared_ptr

/**
 * @class ProfileManager
 * @brief Централизованный сервис для загрузки, парсинга и кэширования профилей.
 * @details Этот класс НЕ является синглтоном. Предполагается, что будет создан
 *          один экземпляр в главном окне приложения, который будет передаваться
 *          всем, кому он нужен. Класс является потокобезопасным.
 */
class ProfileManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор.
     * @param parent Родительский QObject.
     */
    explicit ProfileManager(QObject* parent = nullptr);
    ~ProfileManager() override;

    /**
     * @brief Загружает профиль для сбора ресурсов из JSON-файла.
     * @details Если профиль уже был загружен ранее, он будет взят из кэша.
     *          Метод является потокобезопасным.
     * @param path Полный путь к .json файлу профиля.
     * @return Умный указатель (shared_ptr) на загруженный профиль или nullptr в случае ошибки.
     */
    std::shared_ptr<GatheringProfile> getGatheringProfile(const QString& path);

    /**
     * @brief Загружает профиль для гринда мобов из JSON-файла.
     * @details Аналогичен getGatheringProfile, но работает с GrindingProfile.
     *          Потокобезопасен и использует кэширование.
     * @param path Полный путь к .json файлу профиля.
     * @return Умный указатель на загруженный профиль или nullptr в случае ошибки.
     */
    std::shared_ptr<GrindingProfile> getGrindingProfile(const QString& path);

   private:
    /**
     * @brief Внутренний метод, который непосредственно выполняет парсинг JSON-файла.
     * @param path Путь к файлу.
     * @return Указатель на созданный профиль или nullptr.
     */
    std::shared_ptr<GatheringProfile> parseGatheringProfile(const QString& path);

    /**
     * @brief Внутренний метод для парсинга JSON-файла профиля гринда.
     * @param path Путь к файлу.
     * @return Указатель на созданный профиль или nullptr.
     */
    std::shared_ptr<GrindingProfile> parseGrindingProfile(const QString& path);

    /// @brief Кэш для хранения уже загруженных профилей. Ключ - путь к файлу.
    QMap<QString, std::shared_ptr<GatheringProfile>> m_loadedProfiles;
    QMap<QString, std::shared_ptr<GrindingProfile>> m_grindingProfileCache;

    /// @brief "Ключ от комнаты" для защиты от одновременного доступа к кэшу из разных потоков.
    QMutex m_mutex;
};