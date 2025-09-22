#pragma once

#include <QObject>
#include <cstdint>
#include "core/SharedMemoryManager/SharedMemoryManager.h"

/**
 * @class InteractionManager
 * @brief "Мышцы" бота, отвечающие за все виды взаимодействия с игровым миром.
 * @details Этот менеджер отправляет в DLL низкоуровневые команды для выполнения
 *          действий, таких как сбор руды, лутинг, разговор с NPC и т.д.,
 *          используя прямые вызовы функций игры.
 */
class InteractionManager : public QObject
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор.
     * @param sharedMemory Указатель на менеджер общей памяти для отправки команд в DLL.
     * @param parent Родительский QObject.
     */
    explicit InteractionManager(SharedMemoryManager* sharedMemory, QObject* parent = nullptr);

    /**
     * @brief Отправляет команду на "правый клик" по цели.
     * @details Вызывает нативную функцию InteractByGUID в клиенте. Универсальное
     *          действие для сбора, лута, разговора с NPC и атаки (если цель враждебна).
     * @param targetGuid GUID цели для взаимодействия.
     * @return true, если команда успешно отправлена в DLL.
     */
    bool interactWithTarget(uint64_t targetGuid);

   private:
    /// @brief Указатель на общую память для связи с DLL.
    SharedMemoryManager* m_sharedMemory;
};