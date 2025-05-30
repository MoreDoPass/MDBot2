#include "PlayerDataSource.h"
#include "EditorPlayerPointerHook.h"  // Включаем наш новый класс хука
#include <QLoggingCategory>

// Объявляем категорию логирования (можно и в .h, если используется в нескольких местах)
Q_LOGGING_CATEGORY(playerDataSourceLog, "mapeditor.playerdatasource")

namespace MapEditor
{
namespace PlayerCore
{

// Адрес функции для хука (из CharacterHook.h)
constexpr uintptr_t FunctionAddressToHook = 0x57C6E0;

PlayerDataSource::PlayerDataSource(MemoryManager* memoryManager, QObject* parent)
    : QObject(parent),
      m_memoryManager(memoryManager),
      m_currentPid(0),
      m_hookMemoryForPointer(nullptr),
      m_playerBaseHook(nullptr),  // Инициализируем новым типом
      m_isHookSet(false),
      m_playerBaseAddress(0)
{
    qCInfo(playerDataSourceLog) << "PlayerDataSource constructor called.";
    if (!m_memoryManager)
    {
        qCCritical(playerDataSourceLog) << "MemoryManager is nullptr!";
    }
}

PlayerDataSource::~PlayerDataSource()
{
    qCInfo(playerDataSourceLog) << "PlayerDataSource destructor called.";
    uninstallPlayerPointerHook();  // Гарантируем снятие хука и освобождение памяти
}

bool PlayerDataSource::setActiveProcess(DWORD pid)
{
    qCInfo(playerDataSourceLog) << "setActiveProcess called with PID:" << pid;
    if (m_currentPid == pid && m_isHookSet)
    {
        qCInfo(playerDataSourceLog) << "Process" << pid << "is already active and hook is set.";
        return true;
    }

    qCInfo(playerDataSourceLog) << "Uninstalling previous hook (if any) for PID:" << m_currentPid;
    uninstallPlayerPointerHook();
    m_currentPid = pid;
    m_playerBaseAddress = 0;
    m_currentPosition = QVector3D();  // Сбрасываем позицию при смене процесса

    if (!m_memoryManager)
    {
        qCCritical(playerDataSourceLog) << "MemoryManager is null in setActiveProcess!";
        emit errorOccurred(QString("Internal error: MemoryManager is null."));
        return false;
    }

    if (!m_memoryManager->isProcessOpen() || m_memoryManager->pid().value_or(0) != pid)
    {
        QString errorMsg = QString("MemoryManager not open for PID %1 or PID mismatch (MM PID: %2)")
                               .arg(pid)
                               .arg(m_memoryManager->pid().value_or(0));
        emit errorOccurred(errorMsg);
        qCWarning(playerDataSourceLog) << errorMsg;
        return false;
    }

    qCInfo(playerDataSourceLog) << "Attempting to install player pointer hook for PID:" << pid;
    if (installPlayerPointerHook())
    {
        qCInfo(playerDataSourceLog) << "Player pointer hook successfully installed for PID:" << pid
                                    << "m_isHookSet:" << m_isHookSet
                                    << "m_playerBaseAddress (initial from hook memory):" << Qt::hex
                                    << getPlayerBaseFromHook();
        return true;
    }

    QString errorMsg = QString("Failed to install player pointer hook for PID %1.").arg(pid);
    emit errorOccurred(errorMsg);
    qCWarning(playerDataSourceLog) << errorMsg;
    qCWarning(playerDataSourceLog) << "m_isHookSet after failed install:" << m_isHookSet;
    return false;
}

void PlayerDataSource::updatePosition()
{
    // qCDebug(playerDataSourceLog) << "updatePosition called."; // Можно раскомментировать для очень детального лога
    if (m_currentPid == 0)
    {
        // qCWarning(playerDataSourceLog) << "updatePosition: No active PID (m_currentPid is 0).";
        return;
    }
    if (!m_isHookSet)
    {
        // qCWarning(playerDataSourceLog) << "updatePosition: Hook is not set (m_isHookSet is false) for PID:" <<
        // m_currentPid;
        return;
    }
    if (!m_memoryManager || !m_memoryManager->isProcessOpen())
    {
        qCWarning(playerDataSourceLog) << "updatePosition: MemoryManager is null or not open for PID:" << m_currentPid;
        return;
    }

    uintptr_t playerPtr = getPlayerBaseFromHook();
    if (!playerPtr)
    {
        // qCDebug(playerDataSourceLog) << "updatePosition: getPlayerBaseFromHook() returned 0. Player likely not in
        // world or hook data not ready."; Сбрасываем текущую позицию, если указатель стал нулевым, чтобы не
        // использовать старые данные
        if (!m_currentPosition.isNull())
        {
            // qCDebug(playerDataSourceLog) << "updatePosition: Player pointer became null, resetting currentPosition.";
            m_currentPosition = QVector3D();  // isNull() вернет true
            // Возможно, стоит уведомить об "исчезновении" игрока, если это важно
            // emit playerVanished();
        }
        return;
    }

    if (playerPtr != m_playerBaseAddress)
    {
        qCDebug(playerDataSourceLog) << "updatePosition: Player base address updated by hook from:" << Qt::hex
                                     << m_playerBaseAddress << "to:" << Qt::hex << playerPtr;
        m_playerBaseAddress = playerPtr;
    }

    if (!m_playerBaseAddress)  // Дополнительная проверка, хотя playerPtr уже проверен
    {
        qCWarning(playerDataSourceLog) << "updatePosition: m_playerBaseAddress is 0 after hook update.";
        return;
    }

    float x, y, z;
    uintptr_t addrX = m_playerBaseAddress + m_coordOffsets.posX;
    uintptr_t addrY = m_playerBaseAddress + m_coordOffsets.posY;
    uintptr_t addrZ = m_playerBaseAddress + m_coordOffsets.posZ;

    // qCDebug(playerDataSourceLog) << "updatePosition: Reading coords from base:" << Qt::hex << m_playerBaseAddress
    //                            << "Offsets X:" << m_coordOffsets.posX << "Y:" << m_coordOffsets.posY << "Z:" <<
    //                            m_coordOffsets.posZ
    //                            << "Reading from AddrX:" << Qt::hex << addrX << "AddrY:" << addrY << "AddrZ:" <<
    //                            addrZ;

    bool readX = m_memoryManager->readMemory(addrX, x);
    bool readY = m_memoryManager->readMemory(addrY, y);
    bool readZ = m_memoryManager->readMemory(addrZ, z);

    if (readX && readY && readZ)
    {
        QVector3D newPosition(x, y, z);
        // qCDebug(playerDataSourceLog) << "updatePosition: Successfully read coords: (" << x << "," << y << "," << z <<
        // ")";
        if (newPosition != m_currentPosition || m_currentPosition.isNull())  // Обновляем, если изменилась или была null
        {
            // Только если позиция действительно изменилась или была невалидной, логируем и эмитим
            if (m_currentPosition.isNull() && !newPosition.isNull())
            {
                qCInfo(playerDataSourceLog) << "updatePosition: Player position ACQUIRED:" << newPosition;
            }
            else if (newPosition != m_currentPosition)
            {
                qCDebug(playerDataSourceLog)
                    << "updatePosition: Player position CHANGED from" << m_currentPosition << "to:" << newPosition;
            }
            m_currentPosition = newPosition;
            emit positionUpdated(m_currentPosition);
        }
    }
    else
    {
        qCWarning(playerDataSourceLog) << "updatePosition: Failed to read one or more coordinates."
                                       << "ReadX:" << readX << "(Addr:" << Qt::hex << addrX << ")"
                                       << "ReadY:" << readY << "(Addr:" << Qt::hex << addrY << ")"
                                       << "ReadZ:" << readZ << "(Addr:" << Qt::hex << addrZ << ")";
        // Если чтение не удалось, возможно, стоит сбросить m_currentPosition, чтобы isNull() стало true
        // m_currentPosition = QVector3D();
        // emit errorOccurred("Failed to read player coordinates.");
    }
}

// --- Приватные методы для хука ---

bool PlayerDataSource::installPlayerPointerHook()
{
    if (m_isHookSet || !m_memoryManager || !m_memoryManager->isProcessOpen())
    {
        qCWarning(playerDataSourceLog) << "Хук уже установлен или MemoryManager не готов.";
        return m_isHookSet;  // Если уже установлен, то true
    }

    // Убедимся, что старый хук (если вдруг остался) удален
    if (m_playerBaseHook)
    {
        delete m_playerBaseHook;
        m_playerBaseHook = nullptr;
    }

    // 1. Выделить память в целевом процессе для хранения указателя на игрока
    // Убедимся, что старая память освобождена, если есть
    if (m_hookMemoryForPointer)
    {
        m_memoryManager->freeMemory(m_hookMemoryForPointer);
        m_hookMemoryForPointer = nullptr;
    }
    m_hookMemoryForPointer = m_memoryManager->allocMemory(sizeof(uintptr_t));
    if (!m_hookMemoryForPointer)
    {
        qCCritical(playerDataSourceLog) << "Не удалось выделить память в целевом процессе для указателя хука!";
        return false;
    }
    qCInfo(playerDataSourceLog) << "Память для указателя хука выделена по адресу:" << Qt::hex
                                << reinterpret_cast<uintptr_t>(m_hookMemoryForPointer);

    // 2. Создать и установить EditorPlayerPointerHook
    m_playerBaseHook = new EditorPlayerPointerHook(
        FunctionAddressToHook, reinterpret_cast<uintptr_t>(m_hookMemoryForPointer), m_memoryManager);

    if (m_playerBaseHook && m_playerBaseHook->install())
    {
        m_isHookSet = true;
        qCInfo(playerDataSourceLog) << "EditorPlayerPointerHook успешно установлен.";
        return true;
    }
    else
    {
        qCCritical(playerDataSourceLog) << "Не удалось установить EditorPlayerPointerHook!";
        if (m_playerBaseHook)
        {
            delete m_playerBaseHook;
            m_playerBaseHook = nullptr;
        }
        // Если хук не установился, освобождаем выделенную память
        if (m_hookMemoryForPointer)
        {
            m_memoryManager->freeMemory(m_hookMemoryForPointer);
            m_hookMemoryForPointer = nullptr;
        }
        m_isHookSet = false;  // Явно ставим false
        return false;
    }
}

void PlayerDataSource::uninstallPlayerPointerHook()
{
    if (m_playerBaseHook)  // Проверяем, что указатель не нулевой
    {
        if (m_isHookSet)  // Пытаемся снять хук только если он был установлен
        {
            m_playerBaseHook->uninstall();
            qCInfo(playerDataSourceLog) << "EditorPlayerPointerHook снят.";
        }
        delete m_playerBaseHook;
        m_playerBaseHook = nullptr;
    }

    if (m_hookMemoryForPointer && m_memoryManager && m_memoryManager->isProcessOpen())
    {
        // Проверяем, открыт ли еще процесс, прежде чем пытаться освободить память
        // (хотя MemoryManager::freeMemory должен сам это обработать)
        m_memoryManager->freeMemory(m_hookMemoryForPointer);
        qCInfo(playerDataSourceLog) << "Память для указателя хука освобождена:" << Qt::hex
                                    << reinterpret_cast<uintptr_t>(m_hookMemoryForPointer);
    }
    m_hookMemoryForPointer = nullptr;  // Всегда обнуляем
    m_isHookSet = false;
    m_playerBaseAddress = 0;  // Также сбрасываем базовый адрес игрока
}

uintptr_t PlayerDataSource::getPlayerBaseFromHook()
{
    if (!m_isHookSet || !m_hookMemoryForPointer || !m_memoryManager || !m_memoryManager->isProcessOpen())
    {
        // qCDebug(playerDataSourceLog) << "getPlayerBaseFromHook: Cannot get_player_base, hook not properly set or MM
        // not ready.";
        return 0;
    }
    uintptr_t playerBase = 0;
    if (m_memoryManager->readMemory(reinterpret_cast<uintptr_t>(m_hookMemoryForPointer), playerBase))
    {
        // qCDebug(playerDataSourceLog) << "getPlayerBaseFromHook: Read player base" << Qt::hex << playerBase << "from"
        // << Qt::hex << reinterpret_cast<uintptr_t>(m_hookMemoryForPointer);
        return playerBase;
    }
    // qCWarning(playerDataSourceLog) << "getPlayerBaseFromHook: Failed to read player base from" << Qt::hex <<
    // reinterpret_cast<uintptr_t>(m_hookMemoryForPointer);
    return 0;
}

}  // namespace PlayerCore
}  // namespace MapEditor