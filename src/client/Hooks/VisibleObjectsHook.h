#pragma once
#include "Core/Hooking/InlineHook.h"
#include <set>
#include <cstdint>
#include <windows.h>  // Для CRITICAL_SECTION

/**
 * @class VisibleObjectsHook
 * @brief Хук-сборщик. Устанавливается на часто вызываемую функцию перебора объектов.
 * @details Его единственная задача - максимально быстро собрать уникальные указатели
 * на объекты, которые игра обрабатывает в данный момент, и сложить их в std::set.
 */
class VisibleObjectsHook : public InlineHook
{
   public:
    VisibleObjectsHook();
    ~VisibleObjectsHook();

    /**
     * @brief Потокобезопасно забирает накопленный набор указателей и очищает внутренний контейнер.
     * @return Копия std::set с указателями на объекты, видимые с момента последнего вызова.
     */
    std::set<uintptr_t> getAndClearObjects();

   protected:
    /**
     * @brief Обработчик хука. Вызывается для каждого объекта.
     * @details Считывает указатель на объект из регистра ESI и добавляет в set.
     * @param regs Указатель на сохраненные регистры.
     */
    void handler(const Registers* regs) override;

   private:
    /// @brief Контейнер для хранения уникальных указателей на видимые объекты.
    std::set<uintptr_t> m_visibleObjects;
    /// @brief Критическая секция для потокобезопасного доступа к m_visibleObjects.
    CRITICAL_SECTION m_lock;
};