#include "TeleportExecutor.h"
#include "core/MemoryManager/MemoryManager.h"  // Подключаем полный заголовок
#include <QThread>
#include <cmath>
#include <stdexcept>

/**
 * @brief Категория логирования для TeleportExecutor.
 */
Q_LOGGING_CATEGORY(logTeleportExecutor, "core.bot.movement.teleport.executor")

// === Вспомогательные функции для работы с WinAPI ===
namespace
{
/**
 * @brief Структура для передачи данных в callback-функцию перечисления окон.
 */
struct FindWoWWindowData
{
    DWORD pid;   ///< PID процесса, окно которого мы ищем.
    HWND found;  ///< Сюда будет записан HWND найденного окна.
};

/**
 * @brief Callback-функция, вызываемая для каждого окна верхнего уровня.
 * @details Проверяет, принадлежит ли окно искомому процессу и имеет ли оно нужный класс.
 * @param hwnd Хендл текущего окна.
 * @param lParam Указатель на структуру FindWoWWindowData.
 * @return TRUE для продолжения перечисления, FALSE для остановки.
 */
BOOL CALLBACK FindWoWWindowProc(HWND hwnd, LPARAM lParam)
{
    auto* data = reinterpret_cast<FindWoWWindowData*>(lParam);
    DWORD winPid = 0;
    GetWindowThreadProcessId(hwnd, &winPid);

    // Если PID окна совпадает с искомым
    if (winPid == data->pid)
    {
        char className[128] = {0};
        GetClassNameA(hwnd, className, sizeof(className));
        // Проверяем, что это игровое окно (основное, не лаунчер)
        if (strcmp(className, "GxWindowClassD3d") == 0 || strcmp(className, "GxWindowClass") == 0)
        {
            data->found = hwnd;
            return FALSE;  // Нашли, останавливаем перебор
        }
    }
    return TRUE;  // Продолжаем перебор
}

/**
 * @brief Находит HWND главного окна игры по её PID.
 * @param pid Идентификатор процесса игры.
 * @return HWND окна или nullptr, если не найдено.
 */
HWND findWoWWindow(DWORD pid)
{
    FindWoWWindowData data{pid, nullptr};
    EnumWindows(FindWoWWindowProc, reinterpret_cast<LPARAM>(&data));
    return data.found;
}

/**
 * @brief Отправляет событие нажатия или отжатия клавиши в окно.
 * @param hwnd Хендл окна-получателя.
 * @param vk Виртуальный код клавиши.
 * @param press true для нажатия (WM_KEYDOWN), false для отжатия (WM_KEYUP).
 */
void sendKeyToWoW(HWND hwnd, WORD vk, bool press)
{
    if (!IsWindow(hwnd)) return;
    if (press)
        PostMessage(hwnd, WM_KEYDOWN, vk, 0);
    else
        PostMessage(hwnd, WM_KEYUP, vk, 0);
}

// Смещения координат в структуре игрока WoW 3.3.5a
// Они идентичны тем, что в Character.h, но для независимости компонента дублируем их здесь.
namespace PlayerOffsets
{
constexpr uintptr_t X = 0x798;
constexpr uintptr_t Y = 0x79C;
constexpr uintptr_t Z = 0x7A0;
}  // namespace PlayerOffsets

}  // namespace

/**
 * @brief Конструктор исполнителя телепортации.
 * @param memoryManager Указатель на MemoryManager.
 * @param parent Родительский QObject.
 */
TeleportExecutor::TeleportExecutor(MemoryManager* memoryManager, QObject* parent)
    : QObject(parent), m_memoryManager(memoryManager)
{
    if (!m_memoryManager)
    {
        // Используем qFatal для критических ошибок конфигурации, чтобы сразу выявить проблему.
        qFatal("TeleportExecutor initialized with a nullptr MemoryManager!");
    }
    qCInfo(logTeleportExecutor) << "TeleportExecutor created.";
}

/**
 * @brief Основной метод для выполнения пошаговой телепортации.
 */
bool TeleportExecutor::setPositionStepwise(uintptr_t playerBaseAddress, DWORD pid, uintptr_t flagBufferAddress,
                                           float targetX, float targetY, float targetZ, float step)
{
    try
    {
        // --- 1. Валидация входных данных ---
        if (!m_memoryManager || !m_memoryManager->isProcessOpen())
        {
            qCCritical(logTeleportExecutor) << "Teleport failed: MemoryManager is not attached to a process.";
            return false;
        }
        if (playerBaseAddress == 0 || flagBufferAddress == 0)
        {
            qCCritical(logTeleportExecutor) << "Teleport failed: player or flag address is zero.";
            return false;
        }
        if (step <= 0)
        {
            qCWarning(logTeleportExecutor) << "Invalid step" << step << ", defaulting to 10.0f.";
            step = 10.0f;
        }

        // --- 2. Получение текущего состояния ---
        float currentX = 0.0f, currentY = 0.0f, currentZ = 0.0f;
        if (!m_memoryManager->readMemory(playerBaseAddress + PlayerOffsets::X, currentX) ||
            !m_memoryManager->readMemory(playerBaseAddress + PlayerOffsets::Y, currentY) ||
            !m_memoryManager->readMemory(playerBaseAddress + PlayerOffsets::Z, currentZ))
        {
            qCCritical(logTeleportExecutor) << "Teleport failed: could not read current player coordinates.";
            return false;
        }

        HWND hwnd = findWoWWindow(pid);
        if (!hwnd)
        {
            qCCritical(logTeleportExecutor) << "Teleport failed: could not find game window for PID" << pid;
            return false;
        }

        qCInfo(logTeleportExecutor) << "Starting teleport from (" << currentX << "," << currentY << "," << currentZ
                                    << ") to (" << targetX << "," << targetY << "," << targetZ << ") with step" << step;

        // --- 3. Расчет шагов ---
        const float dx = targetX - currentX;
        const float dy = targetY - currentY;
        const float dz = targetZ - currentZ;
        const float dist = std::sqrt(dx * dx + dy * dy + dz * dz);
        int stepsCount = (dist > 0.01f) ? static_cast<int>(dist / step) : 0;
        if (stepsCount < 1 && dist > 0.01f) stepsCount = 1;

        const WORD vkMove = VK_RIGHT;  // Используем стрелку вправо, она реже забиндена на что-то важное
        bool press = true;

        // --- 4. Цикл телепортации ---
        for (int i = 1; i <= stepsCount; ++i)
        {
            const float nextX = currentX + dx * i / stepsCount;
            const float nextY = currentY + dy * i / stepsCount;
            const float nextZ = currentZ + dz * i / stepsCount;

            // Записываем новые координаты
            m_memoryManager->writeMemory(playerBaseAddress + PlayerOffsets::X, nextX);
            m_memoryManager->writeMemory(playerBaseAddress + PlayerOffsets::Y, nextY);
            m_memoryManager->writeMemory(playerBaseAddress + PlayerOffsets::Z, nextZ);

            // Сбрасываем флаг перед ожиданием
            const uint8_t zero_flag = 0;
            m_memoryManager->writeMemory(flagBufferAddress, zero_flag);

            // Ждем, пока хук выставит флаг (игра "приняла" новые координаты)
            // Добавляем таймаут, чтобы не зависнуть навсегда
            int timeout = 100;  // 100 * 5ms = 500ms таймаут
            uint8_t flag_value = 0;
            while (timeout > 0)
            {
                m_memoryManager->readMemory(flagBufferAddress, flag_value);
                if (flag_value == 1) break;

                sendKeyToWoW(hwnd, vkMove, press);
                press = !press;  // Чередуем нажатие/отжатие
                QThread::msleep(5);
                timeout--;
            }

            if (timeout == 0)
            {
                qCWarning(logTeleportExecutor) << "Teleport step timeout! The hook might not be working correctly.";
                // Не прерываем весь телепорт, пытаемся продолжить.
            }
        }

        // Телепортируемся точно в конечную точку
        m_memoryManager->writeMemory(playerBaseAddress + PlayerOffsets::X, targetX);
        m_memoryManager->writeMemory(playerBaseAddress + PlayerOffsets::Y, targetY);
        m_memoryManager->writeMemory(playerBaseAddress + PlayerOffsets::Z, targetZ);

        // После завершения цикла — полное нажатие клавиши, чтобы сдвинуть персонажа и обновить состояние на сервере
        sendKeyToWoW(hwnd, vkMove, true);
        QThread::msleep(50);
        sendKeyToWoW(hwnd, vkMove, false);
        qCInfo(logTeleportExecutor) << "Teleport finished successfully.";

        return true;
    }
    catch (const std::exception& ex)
    {
        qCCritical(logTeleportExecutor) << "An exception occurred during teleport:" << ex.what();
        return false;
    }
}