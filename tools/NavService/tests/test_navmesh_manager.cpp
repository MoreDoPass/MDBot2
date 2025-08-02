// --- Файл: tests/test_navmesh_manager.cpp ---

#include <gtest/gtest.h>
#include <QCoreApplication>  // Нужно для получения пути к исполняемому файлу
#include <QDir>              // Для работы с путями
#include <filesystem>        // Для проверки существования файлов

// Подключаем класс, который мы хотим протестировать
#include "Navigation/NavMeshManager.h"
#include "Utils/Vector.h"  // Нужен для Vector3

// Тестовый набор (fixture) для NavMeshManager.
// Это позволяет нам создавать и настраивать объекты перед каждым тестом.
class NavMeshManagerTest : public ::testing::Test
{
   protected:
    // Эта функция будет вызываться перед каждым тестом в этом наборе.
    void SetUp() override
    {
        // В тестах может не быть QCoreApplication, создадим его "пустышку".
        // Это нужно, чтобы QCoreApplication::applicationDirPath() работал корректно.
        int argc = 1;
        char* argv[] = {(char*)"test", nullptr};
        if (!QCoreApplication::instance())
        {
            app = std::make_unique<QCoreApplication>(argc, argv);
        }

        // Формируем путь к папке с навмешами.
        // Ожидается, что они лежат в `build/navmeshes/` относительно папки с exe.
        QString basePath = QCoreApplication::applicationDirPath();
        QDir dir(basePath);
        // dir.cdUp(); // Если папка build лежит рядом с tests, а не внутри
        m_navMeshPath = dir.filePath("navmeshes").toStdString();

        // Создаем экземпляр нашего менеджера с правильным путем.
        manager = std::make_unique<NavMeshManager>(m_navMeshPath);
    }

    // Эта функция будет вызываться после каждого теста.
    void TearDown() override
    {
        // Очищаем объекты, если это необходимо.
        // Умные указатели сделают это за нас.
        manager.reset();
        app.reset();
    }

    // Объекты, доступные в каждом тесте.
    std::unique_ptr<NavMeshManager> manager;
    std::string m_navMeshPath;
    std::unique_ptr<QCoreApplication> app;
};

// --- Сам тест ---

// TEST_F использует наш тестовый набор NavMeshManagerTest.
// Первый аргумент - имя набора, второй - имя теста.
TEST_F(NavMeshManagerTest, GetNavMeshForMap_ShouldInitializeSuccessfully)
{
    // --- Arrange (Подготовка) ---
    // ID карты, для которой у нас есть файлы навмешей.
    const uint32_t mapId = 530;

    // Выводим в консоль путь, который используем. Помогает при отладке.
    printf("Testing with NavMesh path: %s\n", m_navMeshPath.c_str());

    // --- Act (Действие) ---
    // Вызываем публичный метод, который внутри вызовет наш проблемный initNavMesh.
    // *** ПОСТАВЬ БРЕЙКПОИНТ ЗДЕСЬ ИЛИ ВНУТРИ getNavMeshForMap ***
    dtNavMesh* navMesh = manager->getNavMeshForMap(mapId);

    // --- Assert (Проверка) ---
    // Это главное утверждение теста.
    // Мы проверяем, что указатель на navMesh НЕ является nullptr.
    // Если он nullptr, значит, initNavMesh провалился, и тест упадет с ошибкой.
    ASSERT_NE(navMesh, nullptr) << "getNavMeshForMap() вернул nullptr. Это означает, что внутренняя "
                                << "инициализация (initNavMesh) провалилась. Проверьте исправление "
                                << "`dtNavMeshParams params{};` и пути к файлам.";
}

// --- ТЕСТ 2: Проверка загрузки реальных тайлов ---
TEST_F(NavMeshManagerTest, EnsureTilesLoaded_ShouldLoadTilesFromDisk)
{
    // --- Arrange (Подготовка) ---
    const uint32_t mapId = 530;

    // Используем РЕАЛЬНЫЕ координаты из твоего test_client.cpp,
    // но для Запределья (map 530), а не для Азерота.
    // Примерные валидные координаты для Полуострова Адского Пламени.
    const Vector3 startPos = {-379.0f, 3717.0f, 127.0f};  // Возле Траллмара
    const Vector3 endPos = {-144.0f, 2677.0f, 90.0f};     // Возле Оплота Чести

    // Дополнительная проверка: убедимся, что папка с навмешами для карты 530 существует.
    std::string mapNavMeshDir = m_navMeshPath + "/" + std::to_string(mapId);
    ASSERT_TRUE(std::filesystem::exists(mapNavMeshDir))
        << "Папка с навмешами для карты 530 не найдена по пути: " << mapNavMeshDir;
    ASSERT_TRUE(std::filesystem::is_directory(mapNavMeshDir))
        << "Путь к навмешам для карты 530 не является директорией.";

    // --- Act (Действие) ---
    // Вызываем метод, который должен загрузить тайлы для пути между startPos и endPos.
    // *** ПОСТАВЬ БРЕЙКПОИНТ ЗДЕСЬ И ЗАЙДИ ВНУТРЬ (F11) ***
    manager->ensureTilesLoaded(mapId, startPos, endPos);

    // --- Assert (Проверка) ---
    // Этот тест не имеет явного Assert'а в конце. Его цель - отладка.
    // Мы должны зайти внутрь ensureTilesLoaded и пошагово посмотреть,
    // как он вычисляет тайлы (calcTileLoc), формирует пути (createTilePath)
    // и загружает файлы (loadTileFile).
    // Если программа не упадет и выполнит этот вызов, тест будет считаться пройденным.
    // Для более строгого теста нужно было бы получить доступ к приватным полям
    // и проверить, что `loadedTiles` содержит нужные ID, но для отладки это излишне.
    SUCCEED() << "ensureTilesLoaded выполнился без падений. Проверьте логи на предмет ошибок загрузки тайлов.";
}

// --- НОВЫЙ ТЕСТ 3: Проверка загрузки тайлов с твоими реальными координатами ---
TEST_F(NavMeshManagerTest, EnsureTilesLoaded_WithRealCoordinates)
{
    // --- Arrange (Подготовка) ---
    const uint32_t mapId = 530;

    // Твои реальные координаты
    const Vector3 startPos = {10350.79f, -6383.50f, 38.53f};
    const Vector3 endPos = {10350.69f, -6315.87f, 29.92f};

    printf("Testing tile loading for path from (%f, %f, %f) to (%f, %f, %f)\n", startPos.x, startPos.y, startPos.z,
           endPos.x, endPos.y, endPos.z);

    // --- Act (Действие) & Assert (Проверка) ---
    // Мы можем объединить действие и проверку.
    // Если ensureTilesLoaded выкинет исключение (например, из-за m_navMeshes.at()),
    // тест автоматически провалится.
    ASSERT_NO_THROW({ manager->ensureTilesLoaded(mapId, startPos, endPos); })
        << "ensureTilesLoaded бросил исключение. Это может означать, "
        << "что navMesh не был инициализирован, или произошла другая ошибка.";

    // Если код дошел сюда, значит, падения не было.
    SUCCEED() << "ensureTilesLoaded с реальными координатами выполнился без падений.";
}