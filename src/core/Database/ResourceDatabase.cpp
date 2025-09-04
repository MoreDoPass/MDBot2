// ФАЙЛ: src/core/Database/ResourceDatabase.cpp

#include "ResourceDatabase.h"
#include <algorithm>  // для std::copy_if
#include <iterator>

/**
 * @brief Приватный конструктор. Здесь мы инициализируем нашу "базу данных".
 * @details Этот код выполнится только один раз за все время работы программы.
 */
ResourceDatabase::ResourceDatabase()
{
    // Вся наша "база данных" живет здесь, в одном месте.
    // Если нужно добавить новую руду или траву - это делается только в этом файле.
    m_resources = {
        // --- РУДА (Mining) ---
        {"Медная жила", 2770, {1731, 2055, 3763, 103713, 181248}, "ore", "mining"},
        {"Оловянная жила", 2771, {1732, 2056}, "ore", "mining"},
        {"Серебряная жила", 2775, {1733}, "ore", "mining"},
        {"Железная жила", 2772, {1735}, "ore", "mining"},
        {"Золотая жила", 2776, {1737}, "ore", "mining"},
        {"Мифриловое месторождение", 3858, {2047}, "ore", "mining"},
        {"Залежи истинного серебра", 7641, {2048}, "ore", "mining"},
        {"Ториевая жила", 10620, {2051, 123847, 175404}, "ore", "mining"},

        // --- ТРАВА (Herbalism) ---
        {"Сребролист", 765, {2019}, "herb", "herbalism"},
        {"Земляной корень", 785, {2040, 1621}, "herb", "herbalism"},
        {"Магороза", 2447, {1617, 2029}, "herb", "herbalism"},
        {"Остротерн", 2449, {1619, 2031}, "herb", "herbalism"},
        {"Синяк", 2450, {1620, 2033}, "herb", "herbalism"},
        {"Удавник", 2453, {2021}, "herb", "herbalism"}

        // ... в будущем сюда можно добавлять сундуки, квестовые объекты и т.д.
    };
}

/**
 * @brief Статический метод, который создает и возвращает единственный экземпляр класса.
 * @details Использование 'static' внутри функции гарантирует, что объект 'instance'
 *          будет создан только один раз (потокобезопасно начиная с C++11).
 */
const ResourceDatabase& ResourceDatabase::getInstance()
{
    static ResourceDatabase instance;
    return instance;
}

/**
 * @brief Просто возвращает ссылку на весь вектор с ресурсами.
 */
const std::vector<ResourceData>& ResourceDatabase::getAllResources() const
{
    return m_resources;
}

/**
 * @brief Возвращает новый вектор, содержащий только ресурсы указанной категории.
 */
std::vector<ResourceData> ResourceDatabase::getResourcesByCategory(const std::string& category) const
{
    std::vector<ResourceData> filteredResources;

    // Копируем в новый вектор только те элементы, у которых совпадает категория.
    std::copy_if(m_resources.begin(), m_resources.end(), std::back_inserter(filteredResources),
                 [&category](const ResourceData& data) { return data.category == category; });

    return filteredResources;
}