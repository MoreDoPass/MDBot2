#pragma once
#include "shared/Data/SharedData.h"  // Нужен, так как мы работаем с PlayerData

/**
 * @class CharacterManager
 * @brief Отвечает за сбор всей информации о персонаже игрока.
 * @details Этот класс инкапсулирует логику чтения данных из памяти,
 *          относящихся исключительно к нашему персонажу (здоровье, мана,
 *          позиция, кулдауны и т.д.), и заполняет структуру PlayerData.
 */
class CharacterManager
{
   public:
    /**
     * @brief Конструктор.
     */
    CharacterManager();

    /**
     * @brief Основной метод, который выполняет полный сбор данных о персонаже.
     * @param sharedData Указатель на общую структуру данных, куда будет записан результат.
     * @param playerPtr Указатель на объект нашего персонажа в памяти игры.
     */
    void update(SharedData* sharedData, uintptr_t playerPtr);

   private:
    /**
     * @brief Читает глобальный список кулдаунов персонажа.
     * @details Проходит по связанному списку кулдаунов, начиная со статического указателя,
     *          и фильтрует только активные на данный момент кулдауны.
     * @param playerData Ссылка на структуру, которую нужно заполнить.
     */
    void readPlayerCooldowns(PlayerData& playerData);
};