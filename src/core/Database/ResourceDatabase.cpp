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
        {"Сребролист", 2001, {3725, 1617}, "herb", "herbalism"},
        {"Мироцвет", 2002, {3724, 1618}, "herb", "herbalism"},
        {"Земляной корень", 2003, {3726, 1619}, "herb", "herbalism"},
        {"Магороза", 2004, {3727, 1620}, "herb", "herbalism"},
        {"Остротерн", 2005, {3729, 1621}, "herb", "herbalism"},
        {"Удавник", 2006, {2045}, "herb", "herbalism"},
        {"Синячник", 2007, {3730, 1622}, "herb", "herbalism"},
        {"Дикий сталецвет", 2008, {1623}, "herb", "herbalism"},
        {"Могильный мох", 2009, {1628}, "herb", "herbalism"},
        {"Королевская кровь", 2010, {1624}, "herb", "herbalism"},
        {"Корень жизни", 2011, {2041}, "herb", "herbalism"},
        {"Бледнолист", 2012, {2042}, "herb", "herbalism"},
        {"Златошип", 2013, {2046}, "herb", "herbalism"},
        {"Кадгаров ус", 2014, {2043}, "herb", "herbalism"},
        {"Морозник", 2015, {2044}, "herb", "herbalism"},
        {"Огнецвет", 2016, {2866}, "herb", "herbalism"},
        {"Лиловый лотос", 2017, {142140}, "herb", "herbalism"},
        {"Слезы Артаса", 2018, {142141, 176642}, "herb", "herbalism"},
        {"Солнечник", 2019, {176636, 142142}, "herb", "herbalism"},
        {"Пастушья сумка", 2020, {183046, 142143}, "herb", "herbalism"},
        {"Призрачная поганка", 2021, {142144}, "herb", "herbalism"},
        {"Кровь грома", 2022, {176637, 142145}, "herb", "herbalism"},
        {"Золотой сансам", 2023, {176638, 176583}, "herb", "herbalism"},
        {"Снолист", 2024, {176639, 176584}, "herb", "herbalism"},
        {"Горный серебряный шалфей", 2025, {176640, 176586}, "herb", "herbalism"},
        {"Чумоцвет", 2026, {176641, 176587}, "herb", "herbalism"},
        {"Ледяной зев", 2027, {176588}, "herb", "herbalism"},
        {"Черный лотос", 2028, {176589}, "herb", "herbalism"},
        // --- Burning Crusade ---
        {"Сквернопля", 2029, {183044, 181270}, "herb", "herbalism"},
        {"Сияние грез", 2047, {181271, 183045}, "herb", "herbalism"},
        {"Террошишка", 2030, {181277}, "herb", "herbalism"},
        {"Кисейница", 2031, {183043, 181275}, "herb", "herbalism"},
        {"Огненный зев", 2032, {181276}, "herb", "herbalism"},
        {"Древний лишайник", 2033, {181278}, "herb", "herbalism"},
        {"Пустоцвет", 2034, {181279}, "herb", "herbalism"},
        {"Куст пустопраха", 2035, {185881}, "herb", "herbalism"},

        // --- Wrath of the Lich King ---
        {"Золотой клевер", 2036, {189973}, "herb", "herbalism"},
        {"Огница", 2037, {191303}, "herb", "herbalism"},
        {"Ползучий кошмарник", 2038, {181280}, "herb", "herbalism"},
        {"Тигровая лилия", 2039, {190169}, "herb", "herbalism"},
        {"Манаполох", 2040, {181281}, "herb", "herbalism"},
        {"Роза таландры", 2041, {190170}, "herb", "herbalism"},
        {"Язык аспида", 2042, {191019}, "herb", "herbalism"},
        {"Мерзлая трава", 2043, {190173, 190175}, "herb", "herbalism"},
        {"Личецвет", 2044, {190171}, "herb", "herbalism"},
        {"Ледошип", 2045, {190172}, "herb", "herbalism"},
        {"Северный лотос", 2046, {190176}, "herb", "herbalism"}
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