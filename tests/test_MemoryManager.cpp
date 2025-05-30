#include <QtTest>
#include "core/MemoryManager/MemoryManager.h"
#include "core/ProcessManager/ProcessManager.h"

class TestMemoryManager : public QObject
{
    Q_OBJECT
   private slots:
    void testOpenCloseProcess();
    void testReadWriteInt();
    void testReadWriteInt8();
    void testReadWriteInt16();
    void testReadWriteInt32();
    void testReadWriteInt64();
    void testReadWriteFloat();
    void testReadWriteDouble();
    void testReadWriteChar();
    void testReadWriteBool();
    void testReadWriteString();
    void testAdvancedMemoryOps();
};

void TestMemoryManager::testOpenCloseProcess()
{
    MemoryManager mm;
    QVERIFY(!mm.isProcessOpen());
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.isProcessOpen());
    mm.closeProcess();
    QVERIFY(!mm.isProcessOpen());
}

void TestMemoryManager::testReadWriteInt()
{
    int testValue = 123;
    int buffer = 0;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.writeMemory<int>((uintptr_t)&testValue, 456));
    QVERIFY(mm.readMemory<int>((uintptr_t)&testValue, buffer));
    QCOMPARE(buffer, 456);
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteInt8()
{
    int8_t testValue = -42;
    int8_t buffer = 0;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.writeMemory<int8_t>((uintptr_t)&testValue, 127));
    QVERIFY(mm.readMemory<int8_t>((uintptr_t)&testValue, buffer));
    QCOMPARE(buffer, 127);
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteInt16()
{
    int16_t testValue = -32000;
    int16_t buffer = 0;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.writeMemory<int16_t>((uintptr_t)&testValue, 12345));
    QVERIFY(mm.readMemory<int16_t>((uintptr_t)&testValue, buffer));
    QCOMPARE(buffer, 12345);
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteInt32()
{
    int32_t testValue = -123456789;
    int32_t buffer = 0;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.writeMemory<int32_t>((uintptr_t)&testValue, 987654321));
    QVERIFY(mm.readMemory<int32_t>((uintptr_t)&testValue, buffer));
    QCOMPARE(buffer, 987654321);
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteInt64()
{
    int64_t testValue = -1234567890123456LL;
    int64_t buffer = 0;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.writeMemory<int64_t>((uintptr_t)&testValue, 9876543210123456LL));
    QVERIFY(mm.readMemory<int64_t>((uintptr_t)&testValue, buffer));
    QCOMPARE(buffer, 9876543210123456LL);
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteFloat()
{
    float testValue = 3.14f;
    float buffer = 0.0f;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.writeMemory<float>((uintptr_t)&testValue, 2.718f));
    QVERIFY(mm.readMemory<float>((uintptr_t)&testValue, buffer));
    QCOMPARE(buffer, 2.718f);
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteDouble()
{
    double testValue = 1.23456789;
    double buffer = 0.0;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.writeMemory<double>((uintptr_t)&testValue, 9.87654321));
    QVERIFY(mm.readMemory<double>((uintptr_t)&testValue, buffer));
    QCOMPARE(buffer, 9.87654321);
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteChar()
{
    char testValue = 'A';
    char buffer = 0;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    qDebug() << "[Char] Before write: testValue =" << testValue;
    QVERIFY(mm.writeMemory<char>((uintptr_t)&testValue, 'Z'));
    QVERIFY(mm.readMemory<char>((uintptr_t)&testValue, buffer));
    qDebug() << "[Char] After write/read: buffer =" << buffer;
    QCOMPARE(buffer, 'Z');
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteBool()
{
    bool testValue = false;
    bool buffer = false;
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    QVERIFY(mm.writeMemory<bool>((uintptr_t)&testValue, true));
    QVERIFY(mm.readMemory<bool>((uintptr_t)&testValue, buffer));
    QCOMPARE(buffer, true);
    mm.closeProcess();
}

void TestMemoryManager::testReadWriteString()
{
    char testValue[16] = "TestName";
    char buffer[16] = {0};
    MemoryManager mm;
    QVERIFY(mm.openProcess(GetCurrentProcessId()));
    qDebug() << "[String] Before write: testValue =" << testValue;
    // Запишем новую строку в testValue через запись памяти
    const char* newName = "BotUser";
    QVERIFY(mm.writeMemory((uintptr_t)testValue, newName, strlen(newName) + 1));
    // Прочитаем строку через readMemory для строк
    QVERIFY(mm.readMemory((uintptr_t)testValue, buffer, sizeof(buffer) - 1));
    buffer[sizeof(buffer) - 1] = '\0';  // Гарантируем 0-терминатор
    qDebug() << "[String] After write/read: buffer =" << buffer;
    QCOMPARE(QString::fromLatin1(buffer), QString::fromLatin1(newName));
    mm.closeProcess();
}

void TestMemoryManager::testAdvancedMemoryOps()
{
    // Поиск PID процесса run.exe через ProcessManager
    auto processes = ProcessManager::findProcessesByName(L"run.exe");
    if (processes.empty()) {
        qCCritical(memoryManagerLog) << "Процесс run.exe не найден! Запусти игру и повтори тест.";
        QFAIL("run.exe not found");
        return;
    }
    DWORD pid = processes.front().pid;
    qCInfo(memoryManagerLog) << "Найден PID run.exe:" << pid;

    MemoryManager mm;
    QVERIFY(mm.openProcess(pid));

    // 1. Три аллокации
    void* addr1 = mm.allocMemory(32, PAGE_READWRITE);
    QVERIFY(addr1);
    void* addr2 = mm.allocMemory(32, PAGE_READWRITE);
    QVERIFY(addr2);
    void* addr3 = mm.allocMemory(128, PAGE_READWRITE);
    QVERIFY(addr3);

    // Записываем значения в addr1 и addr2, потом освобождаем
    int val1 = 111, val2 = 222;
    QVERIFY(mm.writeMemory<int>((uintptr_t)addr1, val1));
    QVERIFY(mm.writeMemory<int>((uintptr_t)addr2, val2));
    QVERIFY(mm.freeMemory(addr1));
    QVERIFY(mm.freeMemory(addr2));

    // 2. В addr3 пишем разные типы данных с разными смещениями
    size_t offset = 0;
    QVERIFY(mm.writeMemory<float>((uintptr_t)addr3 + offset, 3.14f)); offset += sizeof(float);
    QVERIFY(mm.writeMemory<double>((uintptr_t)addr3 + offset, 2.718281828)); offset += sizeof(double);
    QVERIFY(mm.writeMemory<int8_t>((uintptr_t)addr3 + offset, -42)); offset += sizeof(int8_t);
    QVERIFY(mm.writeMemory<int16_t>((uintptr_t)addr3 + offset, 12345)); offset += sizeof(int16_t);
    QVERIFY(mm.writeMemory<int32_t>((uintptr_t)addr3 + offset, -987654321)); offset += sizeof(int32_t);
    QVERIFY(mm.writeMemory<int64_t>((uintptr_t)addr3 + offset, 1234567890123456LL)); offset += sizeof(int64_t);
    const char* testStr = "Hello, MDBot2!";
    QVERIFY(mm.writeMemory((uintptr_t)addr3 + offset, testStr, strlen(testStr) + 1));

    // Чтение и вывод
    offset = 0;
    float f = 0; double d = 0; int8_t i8 = 0; int16_t i16 = 0; int32_t i32 = 0; int64_t i64 = 0;
    char str[32] = {0};
    QVERIFY(mm.readMemory<float>((uintptr_t)addr3 + offset, f)); offset += sizeof(float);
    QVERIFY(mm.readMemory<double>((uintptr_t)addr3 + offset, d)); offset += sizeof(double);
    QVERIFY(mm.readMemory<int8_t>((uintptr_t)addr3 + offset, i8)); offset += sizeof(int8_t);
    QVERIFY(mm.readMemory<int16_t>((uintptr_t)addr3 + offset, i16)); offset += sizeof(int16_t);
    QVERIFY(mm.readMemory<int32_t>((uintptr_t)addr3 + offset, i32)); offset += sizeof(int32_t);
    QVERIFY(mm.readMemory<int64_t>((uintptr_t)addr3 + offset, i64)); offset += sizeof(int64_t);
    QVERIFY(mm.readMemory((uintptr_t)addr3 + offset, str, sizeof(str) - 1));
    str[sizeof(str) - 1] = '\0';
    qInfo(memoryManagerLog) << "[Advanced] addr3 =" << addr3;
    qInfo(memoryManagerLog) << "float:" << f << ", double:" << d << ", int8_t:" << i8 << ", int16_t:" << i16
        << ", int32_t:" << i32 << ", int64_t:" << i64 << ", str:" << str;

    // 3. Смена защиты памяти по адресу 0x00400000 и запись NOP
    void* patchAddr = (void*)0x00400000;
    DWORD oldProt = 0;
    QVERIFY(mm.changeMemoryProtection(patchAddr, 10, PAGE_EXECUTE_READWRITE, &oldProt));
    uint8_t nops[10] = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
    QVERIFY(mm.writeMemory((uintptr_t)patchAddr, (const char*)nops, sizeof(nops)));
    // Можно вернуть защиту обратно, если нужно:
    mm.changeMemoryProtection(patchAddr, 10, oldProt);

    mm.closeProcess();
}

QTEST_MAIN(TestMemoryManager)
#include "test_MemoryManager.moc"