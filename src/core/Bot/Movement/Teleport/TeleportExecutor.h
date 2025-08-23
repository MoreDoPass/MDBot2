#pragma once

#include <QObject>
#include <QLoggingCategory>
#include <windows.h>  // Для DWORD

// Прямое объявление, чтобы не подключать тяжелый заголовок
class MemoryManager;

/**
 * @brief Категория логирования для TeleportExecutor.
 * @details Используется для отслеживания процесса пошаговой телепортации.
 */
Q_DECLARE_LOGGING_CATEGORY(logTeleportExecutor)

/**
 * @class TeleportExecutor
 * @brief Выполняет низкоуровневую логику пошаговой телепортации.
 * @details Этот класс является "исполнителем". Он получает команду и все необходимые данные
 * (адреса, PID, координаты) и выполняет пошаговый телепорт, напрямую работая с памятью
 * и отправляя ввод в окно процесса. Он не зависит от высокоуровневой логики бота или GUI.
 */
class TeleportExecutor : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор исполнителя телепортации.
     * @param memoryManager Указатель на MemoryManager для работы с памятью целевого процесса.
     * @param parent Родительский QObject.
     */
    explicit TeleportExecutor(MemoryManager* memoryManager, QObject* parent = nullptr);

    /**
     * @brief Деструктор по умолчанию.
     */
    ~TeleportExecutor() override = default;

    /**
     * @brief Выполняет пошаговый телепорт персонажа к указанным координатам.
     * @param playerBaseAddress Базовый адрес структуры персонажа в памяти.
     * @param pid Идентификатор (PID) процесса игры для поиска окна и отправки ввода.
     * @param flagBufferAddress Адрес в памяти игры, где хук выставляет флаг о "принятии" шага.
     * @param targetX Целевая координата X.
     * @param targetY Целевая координата Y.
     * @param targetZ Целевая координата Z.
     * @param step Дистанция одного шага телепортации (чем меньше, тем безопаснее, но медленнее).
     * @return true, если телепортация успешно завершена, иначе false.
     */
    bool setPositionStepwise(uintptr_t playerBaseAddress, DWORD pid, uintptr_t flagBufferAddress, float targetX,
                             float targetY, float targetZ, float step = 10.0f);

   private:
    /// @brief Указатель на менеджер памяти, через который происходит вся работа с процессом.
    MemoryManager* m_memoryManager;
};