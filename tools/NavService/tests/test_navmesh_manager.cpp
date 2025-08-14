// --- Файл: tests/test_navmesh_manager.cpp ---

#include <gtest/gtest.h>
#include <QCoreApplication>
#include <QDir>
#include <filesystem>
#include <memory>

// Подключаем все классы, которые будем использовать в тестах
#include "Navigation/NavMeshManager.h"
#include "Pathfinder/Pathfinder.h"
#include "Utils/Logger.h"  // <<< Подключаем Logger.h
#include "Utils/Vector.h"

// --- Тестовый набор (fixture) ---
class NavSystemTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        // Создаем "пустышку" QCoreApplication
        int argc = 1;
        char* argv[] = {(char*)"test", nullptr};
        if (!QCoreApplication::instance())
        {
            app = std::make_unique<QCoreApplication>(argc, argv);
        }
        // <<< ИСПРАВЛЕНИЕ: Мы НЕ создаем LoggerManager, а ИНИЦИАЛИЗИРУЕМ статический Logger
        Logger::initialize();

        // Формируем путь к папке с навмешами
        QString basePath = QCoreApplication::applicationDirPath();
        QDir dir(basePath);
        m_navMeshPath = dir.filePath("navmeshes").toStdString();
        printf("Using NavMesh path: %s\n", m_navMeshPath.c_str());

        // Создаем объекты, которые будем тестировать
        manager = std::make_unique<NavMeshManager>(m_navMeshPath);
        pathfinder = std::make_unique<Pathfinder>();
    }

    void TearDown() override
    {
        // <<< ИСПРАВЛЕНИЕ: Мы НЕ очищаем loggerManager, а ВЫКЛЮЧАЕМ статический Logger
        Logger::shutdown();

        // Умные указатели сами все очистят
        pathfinder.reset();
        manager.reset();
        app.reset();
    }

    // Объекты, доступные в каждом тесте
    std::string m_navMeshPath;
    std::unique_ptr<QCoreApplication> app;
    // <<< ИСПРАВЛЕНИЕ: Убираем поле loggerManager, он нам не нужен
    std::unique_ptr<NavMeshManager> manager;
    std::unique_ptr<Pathfinder> pathfinder;
};

// --- ТЕСТ №1: Проверяем, что NavMesh инициализируется без ошибок ---
TEST_F(NavSystemTest, NavMesh_ShouldInitializeSuccessfully)
{
    const uint32_t mapId = 530;
    dtNavMesh* navMesh = manager->getNavMeshForMap(mapId);
    ASSERT_NE(navMesh, nullptr) << "getNavMeshForMap() вернул nullptr. "
                                << "Проверьте MAX_POLYS в NavMeshManager.h и `dtNavMeshParams params{};`.";
}

// --- ТЕСТ №2: Финальный тест-отладчик для поиска полигона ---
TEST_F(NavSystemTest, FindNearestPoly_OnRealTile_ShouldSucceed)
{
    const uint32_t mapId = 530;
    const Vector3 startPos = {10350.79f, -6383.50f, 38.53f};
    const Vector3 endPos = {10350.69f, -6315.87f, 29.92f};

    std::string mapNavMeshDir = m_navMeshPath + "/" + std::to_string(mapId);
    ASSERT_TRUE(std::filesystem::exists(mapNavMeshDir))
        << "Папка с навмешами для карты 530 не найдена: " << mapNavMeshDir;

    dtNavMesh* navMesh = manager->getNavMeshForMap(mapId);
    ASSERT_NE(navMesh, nullptr) << "NavMesh не был инициализирован!";

    ASSERT_NO_THROW(manager->ensureTilesLoaded(mapId, startPos, endPos));

    dtNavMeshQuery navQuery;
    dtStatus status = navQuery.init(navMesh, 16384);
    ASSERT_TRUE(dtStatusSucceed(status)) << "navQuery.init() не удался! Статус: " << status;

    // *** ПОСТАВЬ БРЕЙКПОИНТ НА СЛЕДУЮЩЕЙ СТРОКЕ ***
    std::vector<Vector3> path = pathfinder->findPath(&navQuery, startPos, endPos);

    EXPECT_FALSE(path.empty()) << "Pathfinder не смог найти путь. Зайди внутрь findNearestPoly под отладчиком.";
}
