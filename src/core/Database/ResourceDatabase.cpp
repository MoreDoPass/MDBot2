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
        // --- Классика ---
        {"Медная жила", 1001, {1731, 2055, 3763, 103713, 181248}, "ore", "mining"},
        {"Оловянная жила", 1002, {1732, 2054, 3764, 103711, 181249}, "ore", "mining"},
        {"Серебряная жила", 1003, {1733, 73940, 105569}, "ore", "mining"},
        {"Железная жила", 1004, {1735}, "ore", "mining"},
        {"Золотая жила", 1005, {1734}, "ore", "mining"},
        {"Мифриловое месторождение", 1006, {2040, 123310, 150079, 176645}, "ore", "mining"},
        {"Залежи истинного серебра", 1007, {2047, 123309, 150081, 181108}, "ore", "mining"},
        {"Залежи черного железа", 1008, {165658}, "ore", "mining"},
        {"Ториевая жила", 1009, {324, 123848, 150082, 175404, 176643, 177388}, "ore", "mining"},

        // --- Burning Crusade ---
        {"Залежи оскверненного железа", 1010, {181555}, "ore", "mining"},
        {"Залежи адамантита", 1011, {181556, 181569, 181570}, "ore", "mining"},
        {"Кориевая жила", 1012, {181557}, "ore", "mining"},

        // --- Wrath of the Lich King ---
        {"Залежи кобальта", 1013, {189978, 189979}, "ore", "mining"},
        {"Залежи саронита", 1014, {189980, 189981}, "ore", "mining"},
        {"Титановая жила", 1015, {191133}, "ore", "mining"},

        // --- ТРАВА (Herbalism) ---
        {"Сребролист", 2001, {2019}, "herb", "herbalism"},
        {"Земляной корень", 2002, {1621, 2040}, "herb", "herbalism"},
        {"Магороза", 2003, {1617, 2029}, "herb", "herbalism"},
        {"Остротерн", 2004, {1619, 2031}, "herb", "herbalism"},
        {"Синяк", 2005, {1620, 2033}, "herb", "herbalism"},
        {"Удавник", 2006, {2021}, "herb", "herbalism"}

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