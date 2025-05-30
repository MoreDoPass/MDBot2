#pragma once

#include <QObject>
#include <QVector3D>
#include <QLoggingCategory>

#include "MemoryManager/MemoryManager.h"  // Ожидается из .lib
#include "PlayerTypes.h"                  // Локальные типы и оффсеты
// Для HookManager и InlineHook, если они будут использоваться:
// #include "HookManager/HookManager.h"
// #include "HookManager/Hook/InlineHook/InlineHook.h"

// Вперед объявляем наш класс хука, чтобы не включать его .h сюда без необходимости
// (если только для указателя)
namespace MapEditor
{
namespace PlayerCore
{
class EditorPlayerPointerHook;
}
}  // namespace MapEditor

Q_DECLARE_LOGGING_CATEGORY(playerDataSourceLog)

namespace MapEditor
{
namespace PlayerCore
{

class PlayerDataSource : public QObject
{
    Q_OBJECT
   public:
    explicit PlayerDataSource(MemoryManager* memoryManager, QObject* parent = nullptr);
    ~PlayerDataSource();

    /**
     * @brief Устанавливает активный процесс для чтения данных.
     * @param pid Идентификатор процесса.
     * @return true, если инициализация для процесса прошла успешно (например, хук установлен), иначе false.
     */
    bool setActiveProcess(DWORD pid);

    /**
     * @brief Запрашивает обновление данных о позиции из памяти игры.
     *        При успешном чтении испускает сигнал positionUpdated.
     */
    void updatePosition();

    QVector3D currentPosition() const
    {
        return m_currentPosition;
    }
    bool isHookSet() const
    {
        return m_isHookSet;
    }

   signals:
    void positionUpdated(const QVector3D& position);
    void errorOccurred(const QString& message);

   private:
    // Методы для работы с хуками (если будем использовать этот подход)
    bool installPlayerPointerHook();
    void uninstallPlayerPointerHook();
    uintptr_t getPlayerBaseFromHook();  // Читает указатель, сохраненный хуком

    MemoryManager* m_memoryManager = nullptr;
    DWORD m_currentPid = 0;
    PlayerCoordinateOffsets m_coordOffsets;
    QVector3D m_currentPosition;

    // Данные для хука (аналогично Character.cpp из MDBot2)
    // Эти значения нужно будет настроить!
    static const uintptr_t FunctionAddressToHook_DEPRECATED = 0x4FA64E;  // Адрес функции для хука (ЗАГЛУШКА!)
    void* m_hookMemoryForPointer = nullptr;               // Память в игре для сохранения указателя от хука
    EditorPlayerPointerHook* m_playerBaseHook = nullptr;  // Сам объект хука
    bool m_isHookSet = false;
    uintptr_t m_playerBaseAddress = 0;  // Указатель на структуру игрока, полученный от хука
};

}  // namespace PlayerCore
}  // namespace MapEditor