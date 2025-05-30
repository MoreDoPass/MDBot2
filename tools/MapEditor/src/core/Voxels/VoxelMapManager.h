#ifndef VOXELMAPMANAGER_H
#define VOXELMAPMANAGER_H

#include "VoxelMap.h"  // Включаем определение VoxelMap
#include <QString>
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(voxelMapManagerLog)

/**
 * @brief Класс для управления операциями с воксельными картами (VoxelMap).
 *
 * Отвечает за загрузку, сохранение и, возможно, создание экземпляров VoxelMap.
 */
class VoxelMapManager
{
   public:
    VoxelMapManager();

    /**
     * @brief Загружает данные воксельной карты из файла.
     * @param filePath Путь к файлу с данными карты.
     * @param[out] outVoxelMap Ссылка на объект VoxelMap, в который будут загружены данные.
     * @return true, если загрузка прошла успешно, иначе false.
     */
    bool loadVoxelMap(const QString& filePath, VoxelMap& outVoxelMap);

    /**
     * @brief Сохраняет данные воксельной карты в файл.
     * @param filePath Путь к файлу для сохранения данных карты.
     * @param voxelMap Ссылка на объект VoxelMap, данные которого нужно сохранить.
     * @return true, если сохранение прошло успешно, иначе false.
     */
    bool saveVoxelMap(const QString& filePath, const VoxelMap& voxelMap);

    /**
     * @brief Создает новую воксельную карту с заданными параметрами (опционально).
     *        Этот метод может быть полезен, если создание карты имеет сложную логику,
     *        которую не хочется выносить в конструктор VoxelMap или делать статической.
     * @param origin Начальная точка карты.
     * @param dimensions Размеры карты в вокселях.
     * @param voxelSize Размер вокселя.
     * @param initialState Начальное состояние вокселей.
     * @return Указатель на созданную VoxelMap или nullptr в случае ошибки.
     *         Примечание: Возвращение VoxelMap по значению или через выходной параметр может быть предпочтительнее
     *         в зависимости от управления памятью.
     */
    // VoxelMap createNewVoxelMap(const QVector3D& origin, const QVector3D& dimensions, float voxelSize, VoxelState
    // initialState = VoxelState::UNKNOWN);

   private:
    // Внутренние вспомогательные методы для парсинга форматов файлов и т.д.
};

#endif  // VOXELMAPMANAGER_H
