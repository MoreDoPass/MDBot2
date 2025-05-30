#include <QtTest>
#include "core/MemoryManager/MemoryManager.h"
#include "core/HookManager/Hook/InlineHook/InlineHook.h"
#include "core/ProcessManager/ProcessManager.h"

/**
 * @brief Базовый хук для тестов с простым трамплином
 */
class BasicInlineHook : public InlineHook
{
   public:
    using InlineHook::InlineHook;

   protected:
    bool generateTrampoline() override
    {
        if (!m_trampolinePtr || m_originalBytes.isEmpty())
        {
            qCCritical(inlineHookLog) << "Трамплин не инициализирован или нет оригинальных байт";
            return false;
        }

        size_t offset = 0;
        QByteArray trampolineBytes;

        // Копируем оригинальные байты
        trampolineBytes.append(m_originalBytes);
        offset += m_originalBytes.size();

        // JMP обратно на адрес после патча
        trampolineBytes.append(static_cast<char>(0xE9));  // jmp
        offset++;

        int32_t relJmp = static_cast<int32_t>((m_address + m_patchSize) - (m_trampolinePtr + offset + 4));
        trampolineBytes.append(reinterpret_cast<const char*>(&relJmp), 4);

        // Записываем весь трамплин через MemoryManager
        if (!m_memoryManager->writeMemory(m_trampolinePtr, trampolineBytes.data(), trampolineBytes.size()))
        {
            qCCritical(inlineHookLog) << "Ошибка записи трамплина в память процесса";
            return false;
        }

        qCInfo(inlineHookLog) << "BasicInlineHook трамплин сгенерирован";
        return true;
    }
};

/**
 * @brief Кастомный хук для теста с особым трамплином
 */
class CustomTrampolineHook : public InlineHook
{
   public:
    using InlineHook::InlineHook;

   protected:
    bool generateTrampoline() override
    {
        if (!m_trampolinePtr || m_originalBytes.isEmpty())
        {
            qCCritical(inlineHookLog) << "Трамплин не инициализирован или нет оригинальных байт";
            return false;
        }

        size_t offset = 0;
        QByteArray trampolineBytes;

        // Сохраняем регистры
        trampolineBytes.append(static_cast<char>(0x60));  // pushad
        offset++;

        // Вызываем функцию по адресу 0x400000
        trampolineBytes.append(static_cast<char>(0xE8));  // call
        offset++;

        int32_t relCall = static_cast<int32_t>(0x400000 - (m_trampolinePtr + offset + 4));
        trampolineBytes.append(reinterpret_cast<const char*>(&relCall), 4);
        offset += 4;

        // Выполняем оригинальные байты
        trampolineBytes.append(m_originalBytes);
        offset += m_originalBytes.size();

        // Восстанавливаем регистры
        trampolineBytes.append(static_cast<char>(0x61));  // popad
        offset++;

        // JMP обратно
        trampolineBytes.append(static_cast<char>(0xE9));
        offset++;

        int32_t relJmp = static_cast<int32_t>((m_address + m_patchSize) - (m_trampolinePtr + offset + 4));
        trampolineBytes.append(reinterpret_cast<const char*>(&relJmp), 4);

        // Записываем весь трамплин через MemoryManager
        if (!m_memoryManager->writeMemory(m_trampolinePtr, trampolineBytes.data(), trampolineBytes.size()))
        {
            qCCritical(inlineHookLog) << "Ошибка записи трамплина в память процесса";
            return false;
        }

        qCInfo(inlineHookLog) << "CustomTrampolineHook трамплин сгенерирован";
        return true;
    }
};

class TestInlineHook : public QObject
{
    Q_OBJECT
   private slots:
    void testBaseHook();
    void testCustomHook();
    void testRestoreHook();
};

void TestInlineHook::testBaseHook()
{
    auto processes = ProcessManager::findProcessesByName(L"run.exe");
    QVERIFY(!processes.empty());
    DWORD pid = processes.front().pid;
    MemoryManager mm;
    QVERIFY(mm.openProcess(pid));
    BasicInlineHook hook(0x00400000, 0, &mm);
    QVERIFY(hook.install());
}

void TestInlineHook::testCustomHook()
{
    auto processes = ProcessManager::findProcessesByName(L"run.exe");
    QVERIFY(!processes.empty());
    DWORD pid = processes.front().pid;
    MemoryManager mm;
    QVERIFY(mm.openProcess(pid));
    CustomTrampolineHook hook(0x0040000D, 0, &mm);
    QVERIFY(hook.install());
}

void TestInlineHook::testRestoreHook()
{
    auto processes = ProcessManager::findProcessesByName(L"run.exe");
    QVERIFY(!processes.empty());
    DWORD pid = processes.front().pid;
    MemoryManager mm;
    QVERIFY(mm.openProcess(pid));
    BasicInlineHook hook(0x00400040, 0, &mm);
    QVERIFY(hook.install());
    QVERIFY(hook.uninstall());
}

QTEST_MAIN(TestInlineHook)
#include "test_InlineHook.moc"
