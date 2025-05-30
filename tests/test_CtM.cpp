#include <QtTest>
#include "core/MemoryManager/MemoryManager.h"
#include "core/ProcessManager/ProcessManager.h"
#include "core/Bot/Character/CharacterHook.h"
#include "core/Bot/Movement/CtM/CtMEnablerHook.h"
#include "core/Bot/Movement/CtM/CtM.h"
#include <random>
#include <thread>
#include <chrono>

class TestCtM : public QObject
{
    Q_OBJECT
   private slots:
    void test_CtM_move_random_yard();
};

void TestCtM::test_CtM_move_random_yard()
{
    // 1. Найти процесс WoW (run.exe)
    auto processes = ProcessManager::findProcessesByName(L"run.exe");
    int pid = -1;
    for (const auto& p : processes)
    {
        pid = p.pid;
        break;
    }
    QVERIFY2(pid != -1, "run.exe не найден!");

    // 2. Открыть процесс
    MemoryManager memory;
    QVERIFY2(memory.openProcess(pid), "Не удалось открыть run.exe!");

    // 3. Найти структуру персонажа (через CharacterHook)
    // (Адрес для CharacterHook нужно подобрать под вашу сборку WoW)
    constexpr uintptr_t CHAR_FUNC_ADDR = 0x0057C6E0;  // примерный адрес, заменить на актуальный
    void* savePtr = memory.allocMemory(4);            // под указатель на структуру
    CharacterHook charHook(CHAR_FUNC_ADDR, &memory, reinterpret_cast<uintptr_t>(savePtr));
    QVERIFY2(charHook.install(), "Не удалось установить CharacterHook!");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));  // дать хук сработать
    uintptr_t charStruct = 0;
    QVERIFY(memory.readMemory(reinterpret_cast<uintptr_t>(savePtr), charStruct));
    QVERIFY2(charStruct != 0, "Не удалось получить адрес структуры персонажа!");

    // 4. Прочитать координаты персонажа
    float x = 0, y = 0, z = 0;
    QVERIFY(memory.readMemory(static_cast<uintptr_t>(charStruct + 0x798), x));
    QVERIFY(memory.readMemory(static_cast<uintptr_t>(charStruct + 0x79C), y));
    QVERIFY(memory.readMemory(static_cast<uintptr_t>(charStruct + 0x7A0), z));

    // 5. Случайная точка рядом (1-3 ярда)
    std::mt19937 rng((unsigned)time(nullptr));
    std::uniform_real_distribution<float> dist(1.0f, 3.0f);
    float angle = dist(rng) * 2 * 3.14159f;
    float radius = dist(rng);
    float tx = x + radius * std::cos(angle);
    float ty = y + radius * std::sin(angle);
    float tz = z;

    // 6. Активировать CtMEnablerHook
    CtMEnablerHook ctmEnabler(&memory);
    QVERIFY2(ctmEnabler.install(), "CtMEnablerHook не установился!");

    // 7. Отправить CtM-команду
    CtmExecutor ctmExec(&memory);
    QVERIFY2(ctmExec.moveTo(tx, ty, tz, 0.5f), "CtM moveTo не сработал!");

    // 8. Подождать и проверить движение
    std::this_thread::sleep_for(std::chrono::seconds(2));
    float nx = 0, ny = 0, nz = 0;
    QVERIFY(memory.readMemory(static_cast<uintptr_t>(charStruct + 0x798), nx));
    QVERIFY(memory.readMemory(static_cast<uintptr_t>(charStruct + 0x79C), ny));
    QVERIFY(memory.readMemory(static_cast<uintptr_t>(charStruct + 0x7A0), nz));
    QVERIFY2(std::abs(nx - x) > 0.1f || std::abs(ny - y) > 0.1f, "Координаты не изменились, CtM не сработал!");

    // 9. Очистка
    charHook.uninstall();
    ctmEnabler.uninstall();
    memory.freeMemory(savePtr);
}

QTEST_MAIN(TestCtM)
#include "test_CtM.moc"
