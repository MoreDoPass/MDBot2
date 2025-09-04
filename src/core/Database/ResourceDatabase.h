// ФАЙЛ: src/core/Database/ResourceDatabase.h

#pragma once

#include <string>
#include <vector>

/**
 * @brief Структура, описывающая один ресурс, который можно собирать.
 * @details Связывает человекочитаемое имя, ID предмета и список ID игровых объектов.
 */
struct ResourceData
{
    /** @brief Имя для отображения в GUI (например, "Медная руда"). */
    std::string displayName;

    /** @brief ID предмета, который попадает в сумку (для аукциона и т.д.). */
    int itemId;

    /** @brief Список всех ID игровых ОБЪЕКТОВ, из которых добывается этот предмет. */
    std::vector<int> objectEntryIds;

    /** @brief Категория для фильтрации в GUI (например, "ore", "herb"). */
    std::string category;

    /** @brief Требуемая профессия для сбора (например, "mining", "herbalism"). */
    std::string skill;
};

/**
 * @class ResourceDatabase
 * @brief Синглтон-класс для доступа к статической базе данных игровых ресурсов.
 * @details Предоставляет единый источник правды о том, какие ресурсы (руда, трава) существуют в игре,
 *          какие у них ID предметов и из каких ID объектов они добываются.
 */
class ResourceDatabase
{
   public:
    /**
     * @brief Получить единственный экземпляр базы данных.
     * @return Константная ссылка на объект ResourceDatabase.
     */
    static const ResourceDatabase& getInstance();

    /**
     * @brief Получить полный список всех ресурсов.
     * @return Константная ссылка на вектор всех данных о ресурсах.
     */
    const std::vector<ResourceData>& getAllResources() const;

    /**
     * @brief Получить отфильтрованный список ресурсов по категории.
     * @param category Категория для фильтрации (например, "ore").
     * @return Вектор с данными о ресурсах, подходящих под категорию.
     */
    std::vector<ResourceData> getResourcesByCategory(const std::string& category) const;

    // Запрещаем копирование и присваивание, чтобы гарантировать единственность экземпляра.
    ResourceDatabase(const ResourceDatabase&) = delete;
    void operator=(const ResourceDatabase&) = delete;

   private:
    /**
     * @brief Приватный конструктор. Вызывается один раз при первом вызове getInstance().
     * @details Именно здесь происходит вся инициализация базы данных.
     */
    ResourceDatabase();

    /// @brief Вектор, в котором хранятся все данные о ресурсах.
    std::vector<ResourceData> m_resources;
};