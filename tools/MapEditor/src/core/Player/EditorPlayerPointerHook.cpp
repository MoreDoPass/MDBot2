#include "EditorPlayerPointerHook.h"
#include "MemoryManager/MemoryManager.h"  // Из Core_MemoryManager.lib
#include <QByteArray>
#include <QLoggingCategory>

// Объявляем, что будем использовать категорию, определенную в PlayerDataSource.cpp
Q_DECLARE_LOGGING_CATEGORY(playerDataSourceLog)

// Если будет своя категория логирования
// Q_LOGGING_CATEGORY(editorHookLog, "mapeditor.player.hook")
// Используем существующую категорию из InlineHook или PlayerDataSource для простоты
// Q_LOGGING_CATEGORY(playerDataSourceLog)  // Предполагаем, что она видна здесь

namespace MapEditor
{
namespace PlayerCore
{

EditorPlayerPointerHook::EditorPlayerPointerHook(uintptr_t addressToHook, uintptr_t addressToStoreEax,
                                                 MemoryManager* memoryManager)
    : InlineHook(addressToHook, 0, memoryManager),  // trampolinePtr базового класса будет перезаписан
      m_addressToStoreEax(addressToStoreEax)
{
    if (m_addressToStoreEax == 0)
    {
        qCCritical(playerDataSourceLog) << "EditorPlayerPointerHook: Адрес для сохранения EAX не может быть нулевым!";
        // Можно бросить исключение или установить флаг ошибки
    }
    qCInfo(playerDataSourceLog) << "EditorPlayerPointerHook создан для хука по адресу" << Qt::hex << addressToHook
                                << "с сохранением EAX в" << Qt::hex << m_addressToStoreEax;
}

bool EditorPlayerPointerHook::generateTrampoline()
{
    if (!m_memoryManager || !m_memoryManager->isProcessOpen())
    {
        qCCritical(playerDataSourceLog) << "EditorPlayerPointerHook::generateTrampoline: MemoryManager не готов.";
        return false;
    }

    if (m_trampolinePtr == 0)
    {
        qCCritical(playerDataSourceLog) << "EditorPlayerPointerHook::generateTrampoline: Адрес для кода трамплина не "
                                           "выделен (m_trampolinePtr == 0).";
        return false;
    }

    if (m_originalBytes.isEmpty())
    {
        qCCritical(playerDataSourceLog) << "EditorPlayerPointerHook::generateTrampoline: Оригинальные байты пусты.";
        return false;
    }

    QByteArray trampolineCode;

    // 1. Код для сохранения EAX: mov [m_addressToStoreEax], eax  (A3 xx xx xx xx)
    trampolineCode.append(static_cast<char>(0xA3));
    trampolineCode.append(reinterpret_cast<const char*>(&m_addressToStoreEax), sizeof(m_addressToStoreEax));

    // 2. Оригинальные байты (которые были по адресу m_address и затерты JMP-хуком)
    // Их размер m_patchSize, они хранятся в m_originalBytes
    trampolineCode.append(m_originalBytes);

    // 3. JMP обратно на (m_address + m_patchSize)
    // Адрес назначения: m_address + m_patchSize
    // Адрес текущей инструкции (после JMP): m_trampolinePtr + длина_уже_добавленного_кода + 5 (для JMP)
    uintptr_t jmpBackTargetAddress = m_address + m_patchSize;
    uintptr_t jmpInstructionAddress =
        m_trampolinePtr + trampolineCode.size();  // Адрес, где будет размещена инструкция JMP

    trampolineCode.append(static_cast<char>(0xE9));  // JMP rel32
    int32_t relativeOffset = static_cast<int32_t>(jmpBackTargetAddress - (jmpInstructionAddress + 5));
    trampolineCode.append(reinterpret_cast<const char*>(&relativeOffset), sizeof(relativeOffset));

    // Проверяем, что не вышли за пределы выделенной памяти (в InlineHook::patch выделяется trampolineSize = 64 байта)
    // Это грубая проверка, лучше если бы trampolineSize был доступен здесь.
    if (static_cast<size_t>(trampolineCode.size()) > 60)  // Оставим небольшой запас
    {
        qWarning(playerDataSourceLog) << "EditorPlayerPointerHook::generateTrampoline: Размер кода трамплина ("
                                      << trampolineCode.size() << "байт) близок к лимиту или превышает его.";
    }

    // Записываем сгенерированный код трамплина в выделенную память
    if (!m_memoryManager->writeMemory(m_trampolinePtr, trampolineCode.constData(), trampolineCode.size()))
    {
        qCCritical(playerDataSourceLog)
            << "EditorPlayerPointerHook::generateTrampoline: Не удалось записать код трамплина в память по адресу"
            << Qt::hex << m_trampolinePtr;
        return false;
    }

    qCInfo(playerDataSourceLog)
        << "EditorPlayerPointerHook::generateTrampoline: Код трамплина успешно сгенерирован и записан по адресу"
        << Qt::hex << m_trampolinePtr << "Размер:" << trampolineCode.size() << "байт.";
    return true;
}

}  // namespace PlayerCore
}  // namespace MapEditor